//! `bin/ci-version` decides the version every image is tagged and labelled
//! with. It is shell, so nothing else in this repository type-checks it, and
//! its two failure modes are both silent: a beta that sorts below the release
//! it replaces, and a prerelease suffix the platform's Renovate rule cannot
//! match — which is how `caldav-mcp-beta` sat on a pre-security-fix image
//! while looking maintained.
//!
//! Each test builds a throwaway git repository, because the script's whole
//! input is git history and reading `Cargo.toml`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::path::Path;
use std::process::{Command, Output};

use tempfile::TempDir;

fn git(dir: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn commit(dir: &Path, subject: &str) {
    git(dir, &["commit", "--allow-empty", "-q", "-m", subject]);
}

/// A repository with `cargo_version` in `Cargo.toml`, one commit tagged
/// `v1.2.3`, and then `subjects` on top of it.
fn repo(cargo_version: &str, subjects: &[&str]) -> TempDir {
    let dir = TempDir::new().unwrap();
    let path = dir.path();
    std::fs::write(
        path.join("Cargo.toml"),
        format!("[package]\nname = \"x\"\nversion = \"{cargo_version}\"\n"),
    )
    .unwrap();
    git(path, &["init", "-q", "-b", "main"]);
    git(path, &["config", "user.email", "ci@example.invalid"]);
    git(path, &["config", "user.name", "ci"]);
    git(path, &["config", "commit.gpgsign", "false"]);
    git(path, &["config", "tag.gpgsign", "false"]);
    commit(path, "chore: initial");
    git(path, &["tag", "v1.2.3"]);
    for subject in subjects {
        commit(path, subject);
    }
    dir
}

fn run(dir: &Path, git_ref: &str) -> Output {
    run_with_clock(dir, git_ref, Some("20260826150000"))
}

/// `timestamp: None` exercises the script's own clock. Every other test injects
/// one so it can assert an exact version string, which means none of them can
/// see a change to how the suffix is generated.
fn run_with_clock(dir: &Path, git_ref: &str, timestamp: Option<&str>) -> Output {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("bin/ci-version");
    let mut command = Command::new("bash");
    command
        .arg(script)
        .current_dir(dir)
        .env("GITHUB_REF", git_ref)
        .env_remove("GITHUB_OUTPUT")
        .env_remove("GITHUB_SHA")
        .env_remove("CI_BETA_TIMESTAMP");
    if let Some(timestamp) = timestamp {
        command.env("CI_BETA_TIMESTAMP", timestamp);
    }
    command.output().unwrap()
}

fn outputs(dir: &Path, git_ref: &str) -> HashMap<String, String> {
    let output = run(dir, git_ref);
    assert!(
        output.status.success(),
        "ci-version failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

/// A beta must sort *above* the release it replaces. A prerelease of the
/// version already out sorts below it, so the deployment would read as older
/// than production while running newer code.
#[test]
fn beta_bumps_the_patch_for_an_ordinary_commit() {
    let dir = repo("1.2.3", &["fix: something"]);
    let out = outputs(dir.path(), "refs/heads/beta");
    assert_eq!(out["channel"], "beta");
    assert_eq!(out["bump"], "patch");
    assert_eq!(out["base_tag"], "v1.2.3");
    assert_eq!(out["version"], "1.2.4-beta.20260826150000");
}

#[test]
fn beta_bumps_the_minor_for_a_feat() {
    let dir = repo("1.2.3", &["fix: something", "feat(mcp): a new tool"]);
    let out = outputs(dir.path(), "refs/heads/beta");
    assert_eq!(out["bump"], "minor");
    assert_eq!(out["version"], "1.3.0-beta.20260826150000");
}

#[test]
fn beta_bumps_the_major_for_a_breaking_change() {
    let dir = repo("1.2.3", &["feat!: drop the old tool"]);
    let out = outputs(dir.path(), "refs/heads/beta");
    assert_eq!(out["bump"], "major");
    assert_eq!(out["version"], "2.0.0-beta.20260826150000");
}

/// The base is the newest *stable* tag. Picking the newest tag of any kind
/// would make each beta the base for the next and walk the version away from
/// what was actually released.
#[test]
fn beta_ignores_prerelease_tags_when_choosing_its_base() {
    let dir = repo("1.2.3", &["fix: something"]);
    git(dir.path(), &["tag", "v9.9.9-beta.20260826000000"]);
    let out = outputs(dir.path(), "refs/heads/beta");
    assert_eq!(out["base_tag"], "v1.2.3");
    assert_eq!(out["version"], "1.2.4-beta.20260826150000");
}

/// The platform's `clusters/fondue/*-beta/**` Renovate rule takes
/// `-(beta|alpha)\.\d+$`. A suffix carrying anything but digits parses as
/// semver, is accepted here, and is then unmatchable by the rule that is
/// supposed to maintain the pin — no bump PR is ever opened and the deployment
/// silently stops moving.
#[test]
fn beta_suffix_is_digits_only() {
    let dir = repo("1.2.3", &["fix: something"]);
    // No injected timestamp: this is the only test that reads what the script
    // actually generates, and so the only one that can fail if the suffix
    // format changes.
    let output = run_with_clock(dir.path(), "refs/heads/beta", None);
    assert!(
        output.status.success(),
        "ci-version failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let version = stdout
        .lines()
        .find_map(|line| line.strip_prefix("version="))
        .expect("ci-version must emit a version");
    let (_, suffix) = version.split_once("-beta.").unwrap();
    assert!(
        suffix.len() == 14 && suffix.bytes().all(|b| b.is_ascii_digit()),
        "suffix {suffix:?} must be a 14-digit UTC timestamp or Renovate cannot match the tag"
    );
}

/// A release tag names a version the binary reports from `/health` out of
/// `Cargo.toml`. If they disagree the image cannot correct it, so the build
/// fails rather than publishing the disagreement.
#[test]
fn a_release_tag_must_agree_with_cargo_toml() {
    let dir = repo("1.2.3", &[]);
    let out = outputs(dir.path(), "refs/tags/v1.2.3");
    assert_eq!(out["channel"], "release");
    assert_eq!(out["version"], "1.2.3");

    let mismatch = run(dir.path(), "refs/tags/v9.9.9");
    assert!(!mismatch.status.success());
    let stderr = String::from_utf8_lossy(&mismatch.stderr);
    assert!(
        stderr.contains("does not match Cargo version"),
        "expected a version-disagreement error, got: {stderr}"
    );
}

/// A prerelease release tag is still a release tag, and still has to agree.
#[test]
fn a_prerelease_release_tag_is_accepted_against_the_same_base() {
    let dir = repo("1.2.3", &[]);
    let out = outputs(dir.path(), "refs/tags/v1.2.3-beta.20260826150000");
    assert_eq!(out["version"], "1.2.3-beta.20260826150000");
}

/// With no stable tag there is nothing to bump from, and minting `0.0.1-beta.x`
/// would be inventing a base rather than reading one.
#[test]
fn beta_refuses_when_no_stable_tag_exists() {
    let dir = TempDir::new().unwrap();
    let path = dir.path();
    std::fs::write(
        path.join("Cargo.toml"),
        "[package]\nname = \"x\"\nversion = \"1.2.3\"\n",
    )
    .unwrap();
    git(path, &["init", "-q", "-b", "main"]);
    git(path, &["config", "user.email", "ci@example.invalid"]);
    git(path, &["config", "user.name", "ci"]);
    commit(path, "chore: initial");

    let output = run(path, "refs/heads/beta");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("No stable release tag"),
        "expected a missing-base-tag error"
    );
}

/// Anything that is not a release tag or `beta` produces an unpushed dev
/// version, so a PR build can never publish under a real version.
#[test]
fn other_refs_produce_a_dev_version() {
    let dir = repo("1.2.3", &["fix: something"]);
    let out = outputs(dir.path(), "refs/pull/7/head");
    assert_eq!(out["channel"], "dev");
    assert!(out["version"].starts_with("1.2.3-dev+"));
}
