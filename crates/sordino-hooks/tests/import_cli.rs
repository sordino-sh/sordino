//! Binary-level wiring tests for `sordino-hooks secrets import` — the parts that can
//! only be proven by driving the REAL process: the fail-closed non-interactive gate and
//! the interactive per-value opt-in over a REAL pty. (The pure logic — is_candidate,
//! import_merge, offline resolve, mask proof — is covered by the inline `intake_tests`.)

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_sordino-hooks");

/// A fresh, unique temp dir for one test.
fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("sordino-import-cli-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A candidate-bearing `.env` (a branded sk-live_ key) so the funnel has something to
/// offer — if the gate leaks, this is what would get written.
fn write_candidate_env(dir: &Path) {
    std::fs::write(
        dir.join(".env"),
        "APIKEY=sk-live_deadbeefcafef00dbabe1234\n",
    )
    .unwrap();
}

/// (a) stdin is NOT a tty ⇒ fail closed: nonzero exit, sordino.toml is NEVER written.
#[test]
fn import_non_interactive_stdin_fails_closed() {
    let dir = scratch("noninteractive");
    write_candidate_env(&dir);

    let out = Command::new(BIN)
        .args(["secrets", "import"])
        .env("CLAUDE_PROJECT_DIR", &dir)
        .current_dir(&dir)
        .stdin(Stdio::null()) // definitively not a terminal
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn sordino-hooks");

    let toml_exists = dir.join("sordino.toml").exists();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(!out.status.success(), "non-interactive import must exit nonzero");
    assert!(!toml_exists, "non-interactive import must write NOTHING");
    assert!(
        stderr.contains("needs an interactive terminal"),
        "gate message on stderr, got: {stderr:?}"
    );
}

/// (b) `yes | import` ⇒ piping `y`s through a PIPE (stdin not a tty) does NOT bypass the
/// gate: it refuses and writes nothing. (The stdin gate is what makes this hold even
/// though a bare stdout-only gate would be defeated by `yes |`.)
#[test]
fn import_yes_pipe_still_refuses() {
    let dir = scratch("yespipe");
    write_candidate_env(&dir);

    let mut child = Command::new(BIN)
        .args(["secrets", "import"])
        .env("CLAUDE_PROJECT_DIR", &dir)
        .current_dir(&dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sordino-hooks");

    // Feed a stream of "y" like `yes` would.
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"y\ny\ny\ny\n");
    }
    let status = child.wait().expect("wait");

    let toml_exists = dir.join("sordino.toml").exists();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(!status.success(), "`yes | import` must refuse (stdin not a tty)");
    assert!(!toml_exists, "`yes | import` must write NOTHING");
}

/// (c) REAL pty: answer `y` for the first candidate, `n` for the second ⇒ only the first
/// is written, and NO accepted value ever appears in the written file.
#[test]
fn import_interactive_pty_per_value_opt_in() {
    use portable_pty::{native_pty_system, CommandBuilder, PtySize};

    let dir = scratch("pty");
    // Two candidates, in file order: accept the first, reject the second.
    std::fs::write(
        dir.join(".env"),
        "DATABASE_URL=postgres://user:pass@db.internal:5432/app\n\
         STRIPE_KEY=sk_live_51H8xY2eZvKYlo2C0abcdefghij\n",
    )
    .unwrap();

    let pty = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("openpty");

    let mut cmd = CommandBuilder::new(BIN);
    cmd.arg("secrets");
    cmd.arg("import");
    cmd.env("CLAUDE_PROJECT_DIR", dir.to_str().unwrap());
    cmd.cwd(dir.to_str().unwrap());

    let mut child = pty.slave.spawn_command(cmd).expect("spawn under pty");
    drop(pty.slave);

    // The tty line-discipline buffers input, so writing both answers up front is safe:
    // the child's line-by-line reads pick up "y" then "n" in order.
    {
        let mut writer = pty.master.take_writer().expect("pty writer");
        writer.write_all(b"y\nn\n").expect("write answers");
        writer.flush().ok();
    }

    // Drain the master so the child never blocks writing prompts.
    let mut reader = pty.master.try_clone_reader().expect("pty reader");
    let drain = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = reader.read_to_end(&mut buf);
        buf
    });

    let status = child.wait().expect("wait for child");
    drop(pty.master); // let the drain thread's read_to_end return
    let _ = drain.join();

    let toml = std::fs::read_to_string(dir.join("sordino.toml")).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(status.success(), "interactive import should exit 0");
    assert!(toml.contains("[[secrets]]"), "a stanza was written:\n{toml}");
    assert!(
        toml.contains("name = \"DATABASE_URL\""),
        "the ACCEPTED key is registered:\n{toml}"
    );
    assert!(
        !toml.contains("STRIPE_KEY"),
        "the REJECTED key must NOT be registered:\n{toml}"
    );
    assert!(
        toml.contains("from_ref = \"dotenv:.env#DATABASE_URL\""),
        "a REFERENCE stanza (no value):\n{toml}"
    );
    // No accepted (or rejected) VALUE ever appears in the written file.
    for value in ["postgres://user:pass", "sk_live_51H8xY2eZvKYlo2C0"] {
        assert!(!toml.contains(value), "no value may appear ({value:?}):\n{toml}");
    }
}
