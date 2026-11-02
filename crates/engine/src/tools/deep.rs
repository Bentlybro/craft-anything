//! The Deep-mode hook the native tools consult.
//!
//! When the session is **not** clean-room (Deep mode is on) and Ghidra is installed, the native
//! decompile path prefers Ghidra's result through the *same* tool id (`native_function_pseudocode`),
//! recording `environment.engine = "ghidra"` and a higher confidence. When Deep mode is off, or
//! Ghidra is absent, or anything about the bridge fails, this returns `None` and the caller falls
//! back to the built-in clean-room lifter — the clean-room path is never changed.
//!
//! The Ghidra session is launched lazily on first use and cached on the target, keyed by the
//! target's content and an analysis settings hash. A launch that fails is remembered so we don't
//! retry it on every call.

use crate::settings::Settings;
use crate::tool::{Ctx, ToolOutput};
use craft_anything_engines::ghidra::{self, DeepDecompiler, DeepFunction};
use craft_anything_evidence::{Confidence, Environment, EvidenceBuilder, Limitation, Location, ToolError, host_triple};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// The analysis settings hash for the default Deep profile. Part of the project cache key, so a
/// different pinned language re-analyses rather than reusing the auto-detected project.
fn settings_hash(language_id: Option<&str>) -> String {
    let seed = format!("craft-anything-ghidra-fast-profile-v2|lang={}", language_id.unwrap_or(""));
    craft_anything_evidence::sha256_hex(seed.as_bytes())
}

/// A per-target Ghidra language override set by `core_target_open` (wins over the global setting).
pub struct LanguageOverride(pub String);

/// Cached decision for one target: a live provider, or why there isn't one.
struct DeepSlot {
    provider: Result<Arc<dyn DeepDecompiler>, String>,
}

/// How long Ghidra's one-time analysis of a target may take by default: a big game can take hours,
/// and it's saved, so later sessions open it in moments.
const ANALYSIS_LIMIT_SECS: u64 = 8 * 3600;

/// Why Ghidra wasn't used, as said to the builder. These say only that; the caller adds what it did
/// instead (the built-in decompiler's answer, or that no function was found).
/// Deep mode is on but Ghidra isn't installed.
pub const NOT_INSTALLED: &str = "Deep mode is on, but Ghidra isn't installed. The person can get Ghidra from Settings → Engines.";

/// Get (or lazily create) the deep provider for the active target. `Err(Some(why))`: Deep mode is
/// on but Ghidra can't be used; `Err(None)`: Clean room (never launches). Either way the caller
/// uses the built-in engine.
fn provider_for_active(ctx: &mut Ctx<'_>) -> Result<Arc<dyn DeepDecompiler>, Option<String>> {
    if ctx.session.clean_room() {
        return Err(None);
    }
    // Already decided for this target?
    if let Ok(t) = ctx.session.active()
        && let Some(slot) = t.ext.get::<DeepSlot>()
    {
        return slot.provider.clone().map_err(Some);
    }

    // The target's bytes and identity.
    let (bytes, sha256) = match ctx.session.active() {
        Ok(t) => (t.target.bytes.clone(), t.target.sha256.clone()),
        Err(_) => return Err(None),
    };
    if bytes.is_empty() {
        return remember(ctx, Err("Ghidra needs the program's bytes, which aren't loaded, so the built-in decompiler was used.".into()));
    }

    // A per-target language override (from core_target_open) wins over the global setting.
    let language = ctx.session.active().ok().and_then(|t| t.ext.get::<LanguageOverride>().map(|o| o.0.clone()));
    // Not remembered: once the person installs Ghidra, the next call uses it.
    let Some((cfg, digest)) = config(&ctx.session.settings, language) else {
        return Err(Some(NOT_INSTALLED.into()));
    };
    let cancel = ctx.cancel.clone();
    let cancel_fn = move || cancel.is_cancelled();
    let progress = ctx.progress;
    let report = |f: f32, m: &str| (progress)(crate::tool::Progress { fraction: Some(f), message: m.to_string() });

    match ghidra::Session::start(&cfg, bytes.as_ref(), &sha256, &digest, &cancel_fn, &report) {
        Ok(session) => remember(ctx, Ok(Arc::new(session))),
        // Stopped by the caller: try again next time rather than remembering a failure.
        Err(ghidra::GhidraError::Cancelled) => Err(Some("Ghidra was stopped before it was ready.".into())),
        Err(e) => {
            log::warn!("Deep mode (Ghidra) unavailable; using the built-in engine: {e}");
            remember(ctx, Err(format!("Ghidra couldn't open this program ({e}).")))
        }
    }
}

/// Ghidra's settings for a target (and its analysis settings hash), the same for the app and the
/// builder's tool server so both find one shared analysis. `None`: Ghidra isn't installed.
fn config(settings: &Settings, language_override: Option<String>) -> Option<(ghidra::Config, String)> {
    let g = &settings.engines.ghidra;
    let language_id = language_override.or_else(|| g.language_id.clone());
    let digest = settings_hash(language_id.as_deref());
    let cfg = ghidra::Config {
        analyze_headless: settings.ghidra_launcher()?,
        java_home: settings.ghidra_java(),
        startup_timeout: Duration::from_secs(g.startup_timeout_secs.unwrap_or(ANALYSIS_LIMIT_SECS)),
        store_dir: settings.engine_store_dir(),
        language_id,
        compiler_spec: g.compiler_spec.clone(),
        memory_gb: g.memory_gb,
    };
    Some((cfg, digest))
}

/// Analyse a program with Ghidra ahead of time (Deep mode), so the builder's first decompile opens
/// a saved analysis instead of waiting hours for one. Shares the analysis with any other process
/// doing the same. `progress` gets a line now and then.
pub fn prepare(settings: &Settings, bytes: &[u8], sha256: &str, progress: &(dyn Fn(&str) + Send + Sync)) -> Result<(), String> {
    let (cfg, digest) = config(settings, None).ok_or_else(|| NOT_INSTALLED.to_string())?;
    let never = || false;
    ghidra::analyse(&cfg, bytes, sha256, &digest, &never, &|_, m: &str| progress(m)).map(|_| ()).map_err(|e| e.to_string())
}

fn remember(ctx: &mut Ctx<'_>, provider: Result<Arc<dyn DeepDecompiler>, String>) -> Result<Arc<dyn DeepDecompiler>, Option<String>> {
    if let Ok(t) = ctx.session.active_mut() {
        t.ext.insert(Arc::new(DeepSlot { provider: provider.clone() }));
    }
    provider.map_err(Some)
}

/// An address for the deep engine, and whose address space it is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum At {
    /// The built-in engine's, as every other tool reports it.
    Ours(u64),
    /// Already Ghidra's: the address in a name Ghidra made (`FUN_00101160`).
    Engine(u64),
}

/// Decompile the function at `at` with the deep engine if available. `our_base` is the image
/// base the built-in engine reads the program at; Ghidra may have loaded it elsewhere (a
/// position-independent ELF goes to 0x100000), so addresses are moved between the two.
/// `Err(why)` → the caller uses the built-in lifter and passes on why Ghidra wasn't used (`None`
/// in Clean room). `Ok(Err(..))` only for a cancellation the caller should surface.
pub fn pseudo_code(ctx: &mut Ctx<'_>, at: At, our_base: u64, params: serde_json::Value) -> Result<Result<ToolOutput, ToolError>, Option<String>> {
    let provider = provider_for_active(ctx)?;
    let rebase = ghidra::Rebase::new(our_base, provider.image_base());
    let entry = match at {
        At::Ours(a) => rebase.to_engine(a),
        At::Engine(a) => a,
    };
    match provider.decompile(entry) {
        Ok(Some(df)) => {
            let renames = user_renames(ctx, rebase);
            Ok(build_evidence(ctx, provider.as_ref(), df, rebase, &renames, params))
        }
        Ok(None) => Err(Some("Ghidra had no answer for this function.".into())),
        Err(ghidra::GhidraError::Cancelled) => Ok(Err(ToolError::cancelled())),
        Err(e) => {
            log::warn!("Ghidra decompile failed; falling back to the built-in engine: {e}");
            // A dead bridge (Ghidra crashed or was killed) is started again on the next call; the
            // saved analysis makes that quick.
            if matches!(e, ghidra::GhidraError::Connection(_) | ghidra::GhidraError::Protocol(_))
                && let Ok(t) = ctx.session.active_mut()
            {
                t.ext.remove::<DeepSlot>();
            }
            Err(Some(match e {
                // The bridge looks up the function containing the address and, when its analysis
                // has none, tries to make one there; the message says why it couldn't.
                ghidra::GhidraError::Bridge { ref code, ref message } if code == "not_found" => {
                    format!("Ghidra's analysis has no function at this address and it couldn't make one: {message}.")
                }
                e => format!("Ghidra couldn't decompile this function ({e})."),
            }))
        }
    }
}

/// For each address the person named, the names Ghidra may give it, each with the person's name:
/// the ones Ghidra makes from its own address (`FUN_00101160`, `DAT_…`, `LAB_…`) and the program's
/// own symbol, which Ghidra uses too. Our made-up `sub_…` names are left out; Ghidra never uses them.
fn user_renames(ctx: &mut Ctx<'_>, rebase: ghidra::Rebase) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Ok(st) = super::native_common::native(ctx) else { return out };
    let Ok(t) = ctx.session.active() else { return out };
    for (&a, name) in &t.annotations.names {
        let theirs = rebase.to_engine(a);
        for prefix in ["FUN", "DAT", "LAB"] {
            out.entry(format!("{prefix}_{theirs:08x}")).or_insert_with(|| name.clone());
        }
        if let Some(symbol) = st.prog.name_at(a).filter(|n| n != name && !n.starts_with("sub_")) {
            out.entry(symbol).or_insert_with(|| name.clone());
        }
    }
    out
}

/// A piece of C text: an identifier, or anything else kept as it is (spaces, punctuation, numbers,
/// a whole comment, a whole string or character literal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Piece<'a> {
    Word(&'a str),
    Text(&'a str),
}

/// Split C text into [`Piece`]s. A comment (`//…`, `/*…*/`) or a literal is one piece of text, so
/// nothing inside it is renamed and a quote inside a comment doesn't start a literal.
fn c_pieces(code: &str) -> Vec<Piece<'_>> {
    let b = code.as_bytes();
    let len = b.len();
    let at = |i: usize| b.get(i).copied();
    let ident = |c: Option<u8>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_');
    let mut out = Vec::new();
    // Pieces end only at ASCII bytes, so every slice below is on a character boundary.
    fn push<'a>(out: &mut Vec<Piece<'a>>, code: &'a str, from: usize, to: usize, word: bool) {
        if let Some(s) = code.get(from..to).filter(|s| !s.is_empty()) {
            out.push(if word { Piece::Word(s) } else { Piece::Text(s) });
        }
    }
    let (mut i, mut text_from) = (0usize, 0usize);
    while i < len {
        let c = at(i);
        let next = at(i + 1);
        i = if c == Some(b'/') && next == Some(b'/') {
            (i + 2..len).find(|&j| at(j) == Some(b'\n')).unwrap_or(len)
        } else if c == Some(b'/') && next == Some(b'*') {
            (i + 2..len).find(|&j| at(j) == Some(b'*') && at(j + 1) == Some(b'/')).map_or(len, |j| j + 2)
        } else if c == Some(b'"') || c == Some(b'\'') {
            let mut j = i + 1;
            while j < len && at(j) != c {
                j += if at(j) == Some(b'\\') { 2 } else { 1 };
            }
            (j + 1).min(len)
        } else if c.is_some_and(|c| c.is_ascii_alphabetic() || c == b'_') {
            let end = (i..len).find(|&j| !ident(at(j))).unwrap_or(len);
            push(&mut out, code, text_from, i, false);
            push(&mut out, code, i, end, true);
            text_from = end;
            end
        } else if ident(c) {
            // A number: its digits and suffix (0x401140, 10UL) are text, not a name.
            (i..len).find(|&j| !ident(at(j))).unwrap_or(len)
        } else {
            i + 1
        };
    }
    push(&mut out, code, text_from, len, false);
    out
}

/// `code` with every whole identifier that is a key of `renames` replaced by its value
/// (`check_key` is replaced; `check_key_v2`, `my_check_key`, comments and the text of a string or
/// character literal aren't).
fn rename_identifiers(code: &str, renames: &HashMap<String, String>) -> String {
    if renames.is_empty() {
        return code.to_string();
    }
    c_pieces(code)
        .into_iter()
        .map(|p| match p {
            Piece::Word(w) => renames.get(w).map_or(w, String::as_str),
            Piece::Text(t) => t,
        })
        .collect()
}

/// Whether `s` can stand in C code as a name: letters, digits and `_`, not starting with a digit,
/// and not a C keyword.
fn is_c_name(s: &str) -> bool {
    const KEYWORDS: &[&str] = &[
        "auto", "bool", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum", "extern", "false", "float", "for", "goto",
        "if", "inline", "int", "long", "register", "restrict", "return", "short", "signed", "sizeof", "static", "struct", "switch", "true", "typedef", "union",
        "unsigned", "void", "volatile", "while",
    ];
    s.bytes().next().is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
        && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
        && !KEYWORDS.contains(&s)
}

/// The renames that can go into this code, and the person's names that can't: one that isn't a C
/// name (`handle // note` would turn the rest of a line into a comment), or one that another name
/// in the code already is (it would then name two things). Only names that appear are considered.
fn renames_for_code(texts: &[&str], renames: &HashMap<String, String>) -> (HashMap<String, String>, Vec<String>) {
    let words: std::collections::HashSet<&str> = texts
        .iter()
        .flat_map(|t| c_pieces(t))
        .filter_map(|p| match p {
            Piece::Word(w) => Some(w),
            Piece::Text(_) => None,
        })
        .collect();
    let (mut ok, mut skipped) = (HashMap::new(), Vec::new());
    for (from, to) in renames.iter().filter(|(from, _)| words.contains(from.as_str())) {
        if is_c_name(to) && (!words.contains(to.as_str()) || to == from) {
            ok.insert(from.clone(), to.clone());
        } else if !skipped.contains(to) {
            skipped.push(to.clone());
        }
    }
    skipped.sort();
    (ok, skipped)
}

fn build_evidence(
    ctx: &Ctx<'_>,
    provider: &dyn DeepDecompiler,
    df: DeepFunction,
    rebase: ghidra::Rebase,
    renames: &HashMap<String, String>,
    params: serde_json::Value,
) -> Result<ToolOutput, ToolError> {
    let subject = ctx.session.active()?.target.subject();
    let env = Environment {
        clean_room: false,
        engine: provider.engine().to_string(),
        engine_version: provider.engine_version(),
        host: host_triple(),
        language_id: provider.language_id(),
    };
    let line_count = df.pseudocode.as_deref().map(|p| p.lines().count()).unwrap_or(0);
    // The entry as every other tool gives it; Ghidra's own only when it differs.
    let entry = rebase.from_engine(df.entry);
    // The names the person set, in place of Ghidra's own: as set in the function field and the
    // summary, and in the code wherever they can stand as C names.
    let name = renames.get(&df.name).cloned().unwrap_or_else(|| df.name.clone());
    let texts: Vec<&str> = [Some(df.name.as_str()), df.signature.as_deref(), df.pseudocode.as_deref()].into_iter().flatten().collect();
    let (in_code, not_in_code) = renames_for_code(&texts, renames);
    let signature = df.signature.as_deref().map(|s| rename_identifiers(s, &in_code));
    let pseudocode = df.pseudocode.as_deref().map(|p| rename_identifiers(p, &in_code));
    let renamed = name != df.name || signature != df.signature || pseudocode != df.pseudocode;
    let mut result = serde_json::json!({
        "function": name,
        "entry": format!("{entry:#x}"),
        "signature": signature,
        "pseudo_code": pseudocode,
        "engine": provider.engine(),
    });
    if !rebase.is_identity() {
        result["engine_entry"] = serde_json::json!(format!("{:#x}", df.entry));
    }
    let mut e = EvidenceBuilder::new("native_function_pseudocode", subject, env)
        .params(params)
        .result(result)
        .summary(format!("Pseudo-C for {name} from the Deep engine ({line_count} lines)."))
        // Deep decompilation is derived by a mature external engine: stronger than the built-in
        // inferred lifter, but still a reading aid rather than source.
        .confidence(Confidence::Derived)
        .target_content(true)
        .limitation(Limitation::new("deep_engine", "the pseudo-C comes from the external Deep engine (Ghidra), not the original source"))
        .location(Location::address(entry));
    if !rebase.is_identity() {
        e = e.limitation(Limitation::new(
            "engine_rebased",
            format!(
                "Ghidra loaded this program at {:#x}, not where the built-in engine reads it ({:#x}); entry is the built-in address, engine_entry Ghidra's, and the addresses in Ghidra's names inside the pseudo-C (FUN_…, DAT_…) are Ghidra's",
                rebase.theirs(),
                rebase.ours(),
            ),
        ));
    }
    if renamed {
        e = e.limitation(Limitation::new(
            "user_names_applied",
            "the names you set replace Ghidra's own in this pseudo-C, matched by the name Ghidra gives each address (its FUN_/DAT_/LAB_ name or the program's symbol)",
        ));
    }
    if !not_in_code.is_empty() {
        e = e.limitation(Limitation::new(
            "user_names_not_in_code",
            format!(
                "Ghidra's own name is kept in the code for these names you set, because they aren't C names or the code already uses them for something else: {}",
                not_in_code.join(", ")
            ),
        ));
    }
    if df.created {
        e = e.limitation(Limitation::new(
            "made_on_demand",
            "Ghidra's analysis had no function here, so it made one starting at this address (for this session, never saved); its bounds come from following the code from there",
        ));
    }
    Ok(ToolOutput::evidence(e.build()?))
}

#[cfg(test)]
mod tests {
    use super::super::native_common::test_support::*;
    use super::*;
    use craft_anything_testkit as tk;
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A deep engine that loaded the program at `base`, not where its headers say, as Ghidra does
    /// with a position-independent ELF: it knows only its own addresses, and remembers the last
    /// one it was asked for.
    struct Moved {
        base: u64,
        asked: AtomicU64,
    }

    impl DeepDecompiler for Moved {
        fn engine(&self) -> &'static str {
            "ghidra"
        }
        fn engine_version(&self) -> Option<String> {
            Some("test".into())
        }
        fn image_base(&self) -> Option<u64> {
            Some(self.base)
        }
        fn decompile(&self, entry: u64) -> Result<Option<DeepFunction>, ghidra::GhidraError> {
            self.asked.store(entry, Ordering::SeqCst);
            if entry < self.base {
                return Err(ghidra::GhidraError::Bridge { code: "not_found".into(), message: "the address is not in executable memory".into() });
            }
            let pseudocode = Some(format!("int FUN_{entry:08x}(void) {{ return 0; }}"));
            Ok(Some(DeepFunction { entry, name: format!("FUN_{entry:08x}"), signature: None, pseudocode, created: false }))
        }
        fn list_functions(&self) -> Result<Vec<DeepFunction>, ghidra::GhidraError> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn a_function_named_in_our_addresses_reaches_an_engine_that_loaded_the_program_elsewhere() {
        let (elf, l) = tk::elf64(tk::ElfArch::X86_64, true);
        let e = engine_with("prog", &elf);
        const SHIFT: u64 = 0x10_0000;
        let moved = Arc::new(Moved { base: tk::ELF_BASE + SHIFT, asked: AtomicU64::new(0) });
        {
            let mut s = e.session();
            s.settings.deep_mode = true;
            let provider: Arc<dyn DeepDecompiler> = moved.clone();
            s.active_mut().unwrap().ext.insert(Arc::new(DeepSlot { provider: Ok(provider) }));
        }
        // By name: the engine is asked for its own address, and the answer is in ours.
        let r = call(&e, "native_function_pseudocode", json!({"function": "main"}));
        assert_eq!(r["environment"]["engine"], "ghidra", "{r}");
        assert_eq!(moved.asked.load(Ordering::SeqCst), l.code_va + SHIFT);
        assert_eq!(r["result"]["entry"], format!("{:#x}", l.code_va));
        assert_eq!(r["result"]["engine_entry"], format!("{:#x}", l.code_va + SHIFT));
        let why = r["limitations"].as_array().unwrap().iter().find(|x| x["code"] == "engine_rebased").expect("says the addresses were moved");
        assert!(why.to_string().contains(&format!("{:#x}", tk::ELF_BASE + SHIFT)), "{why}");
        // A name Ghidra made carries Ghidra's address: passed on as it is. (A suffix with a hex
        // letter: one of only digits is read as decimal until #318 is fixed.)
        let ghidra_name = format!("FUN_{:08x}", l.code_va + SHIFT + 0x7a00);
        let r = call(&e, "native_function_pseudocode", json!({"function": ghidra_name}));
        assert_eq!(moved.asked.load(Ordering::SeqCst), l.code_va + SHIFT + 0x7a00);
        assert_eq!(r["result"]["entry"], format!("{:#x}", l.code_va + 0x7a00));
    }

    /// A deep engine at our base that gives the same answer for every function: Ghidra's view of
    /// `main`, calling `helper` by its symbol.
    struct Symbols;

    impl DeepDecompiler for Symbols {
        fn engine(&self) -> &'static str {
            "ghidra"
        }
        fn engine_version(&self) -> Option<String> {
            Some("test".into())
        }
        fn image_base(&self) -> Option<u64> {
            Some(tk::ELF_BASE)
        }
        fn decompile(&self, entry: u64) -> Result<Option<DeepFunction>, ghidra::GhidraError> {
            let pseudocode = Some(
                "int main(void) {
  return helper(5) + helper_count + my_helper();
}"
                .into(),
            );
            Ok(Some(DeepFunction { entry, name: "main".into(), signature: Some("int main(void)".into()), pseudocode, created: false }))
        }
        fn list_functions(&self) -> Result<Vec<DeepFunction>, ghidra::GhidraError> {
            Ok(Vec::new())
        }
    }

    fn with_deep(e: &crate::Engine, provider: Arc<dyn DeepDecompiler>) {
        let mut s = e.session();
        s.settings.deep_mode = true;
        s.active_mut().unwrap().ext.insert(Arc::new(DeepSlot { provider: Ok(provider) }));
    }

    #[test]
    fn ghidra_pseudo_code_uses_the_names_the_person_set_for_its_own_names() {
        let (elf, l) = tk::elf64(tk::ElfArch::X86_64, true);
        let e = engine_with("prog", &elf);
        const SHIFT: u64 = 0x10_0000;
        with_deep(&e, Arc::new(Moved { base: tk::ELF_BASE + SHIFT, asked: AtomicU64::new(0) }));
        call(&e, "native_name_set", json!({"address": format!("{:#x}", l.code_va), "name": "start_here"}));
        // Ghidra calls it FUN_<its own address>: that name is replaced, in the code too.
        for asked in ["main", "start_here"] {
            let r = call(&e, "native_function_pseudocode", json!({"function": asked}));
            assert_eq!(r["environment"]["engine"], "ghidra", "{r}");
            assert_eq!(r["result"]["function"], "start_here", "{r}");
            assert_eq!(r["result"]["pseudo_code"], "int start_here(void) { return 0; }");
            assert_eq!(r["summary"], "Pseudo-C for start_here from the Deep engine (1 lines).");
            assert!(r["limitations"].as_array().unwrap().iter().any(|x| x["code"] == "user_names_applied"), "{r}");
        }
    }

    #[test]
    fn ghidra_pseudo_code_uses_the_names_the_person_set_for_the_programs_symbols() {
        let (elf, _) = tk::elf64(tk::ElfArch::X86_64, true);
        let e = engine_with("prog", &elf);
        with_deep(&e, Arc::new(Symbols));
        let helper = call(&e, "native_function_show", json!({"function": "helper"}))["result"]["entry"].as_str().unwrap().to_string();
        let r = call(&e, "native_function_pseudocode", json!({"function": "main"}));
        assert!(!r["limitations"].as_array().unwrap().iter().any(|x| x["code"] == "user_names_applied"), "nothing named yet: {r}");
        call(&e, "native_name_set", json!({"address": helper, "name": "add_up"}));
        let r = call(&e, "native_function_pseudocode", json!({"function": "main"}));
        // Whole names only: `helper_count` and `my_helper` are other names.
        assert_eq!(
            r["result"]["pseudo_code"],
            "int main(void) {
  return add_up(5) + helper_count + my_helper();
}",
            "{r}"
        );
        assert_eq!(r["result"]["function"], "main");
    }

    #[test]
    fn a_name_that_cant_stand_in_c_or_clashes_stays_out_of_the_code() {
        let (elf, _) = tk::elf64(tk::ElfArch::X86_64, true);
        let e = engine_with("prog", &elf);
        with_deep(&e, Arc::new(Symbols));
        let helper = call(&e, "native_function_show", json!({"function": "helper"}))["result"]["entry"].as_str().unwrap().to_string();
        let main = call(&e, "native_function_show", json!({"function": "main"}))["result"]["entry"].as_str().unwrap().to_string();
        let original = "int main(void) {\n  return helper(5) + helper_count + my_helper();\n}";
        let not_in_code = |r: &serde_json::Value| {
            r["limitations"].as_array().unwrap().iter().find(|x| x["code"] == "user_names_not_in_code").map(|x| x["message"].as_str().unwrap().to_string())
        };
        // Not a C name: the code keeps Ghidra's name, the function field and summary show the person's.
        call(&e, "native_name_set", json!({"address": main, "name": "entry // note"}));
        let r = call(&e, "native_function_pseudocode", json!({"function": "main"}));
        assert_eq!(r["result"]["pseudo_code"], original, "{r}");
        assert_eq!(r["result"]["function"], "entry // note");
        assert_eq!(r["summary"], "Pseudo-C for entry // note from the Deep engine (3 lines).");
        assert!(not_in_code(&r).is_some_and(|m| m.contains("entry // note")), "{r}");
        // A name the code already uses for something else would name two things: left out too.
        call(&e, "native_name_set", json!({"address": main, "name": ""}));
        call(&e, "native_name_set", json!({"address": helper, "name": "helper_count"}));
        let r = call(&e, "native_function_pseudocode", json!({"function": "main"}));
        assert_eq!(r["result"]["pseudo_code"], original, "{r}");
        assert!(not_in_code(&r).is_some_and(|m| m.contains("helper_count")), "{r}");
        // A C keyword isn't a name either.
        call(&e, "native_name_set", json!({"address": helper, "name": "return"}));
        let r = call(&e, "native_function_pseudocode", json!({"function": "main"}));
        assert_eq!(r["result"]["pseudo_code"], original, "{r}");
    }

    #[test]
    fn identifiers_are_renamed_whole() {
        let renames: HashMap<String, String> = [("check_key".to_string(), "verify".to_string()), ("FUN_00101160".to_string(), "go".to_string())].into();
        assert_eq!(
            rename_identifiers("if (check_key(x) && check_key_v2() && !my_check_key) FUN_00101160(\"check_key\");", &renames),
            "if (verify(x) && check_key_v2() && !my_check_key) go(\"check_key\");"
        );
        assert_eq!(rename_identifiers("check_key", &renames), "verify");
        // Comments are kept as they are, and a quote inside one doesn't hide the code after it.
        assert_eq!(
            rename_identifiers("// don't check_key here\ncheck_key(); /* it's check_key */ check_key(0x1f);", &renames),
            "// don't check_key here\nverify(); /* it's check_key */ verify(0x1f);"
        );
        assert_eq!(rename_identifiers("x = 10check_key; /* never closed check_key", &renames), "x = 10check_key; /* never closed check_key");
        assert_eq!(rename_identifiers(r#"puts("a \" check_key"); c = '\''; check_key();"#, &renames), r#"puts("a \" check_key"); c = '\''; verify();"#);
        assert_eq!(rename_identifiers("", &renames), "");
        assert_eq!(rename_identifiers("été check_key", &renames), "été verify");
    }

    #[test]
    fn an_engine_at_our_base_gets_our_addresses_unchanged() {
        let (elf, l) = tk::elf64(tk::ElfArch::X86_64, true);
        let e = engine_with("prog", &elf);
        let same = Arc::new(Moved { base: tk::ELF_BASE, asked: AtomicU64::new(0) });
        {
            let mut s = e.session();
            s.settings.deep_mode = true;
            let provider: Arc<dyn DeepDecompiler> = same.clone();
            s.active_mut().unwrap().ext.insert(Arc::new(DeepSlot { provider: Ok(provider) }));
        }
        let r = call(&e, "native_function_pseudocode", json!({"function": "main"}));
        assert_eq!(same.asked.load(Ordering::SeqCst), l.code_va);
        assert_eq!(r["result"]["entry"], format!("{:#x}", l.code_va));
        assert!(r["result"].get("engine_entry").is_none(), "{r}");
        assert!(!r["limitations"].as_array().unwrap().iter().any(|x| x["code"] == "engine_rebased"));
    }
}
