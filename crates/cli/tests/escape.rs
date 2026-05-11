#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

#[path = "../../../tests/escape/common.rs"]
mod common;

#[path = "../../../tests/escape/read_dotenv.rs"]
mod read_dotenv;

#[path = "../../../tests/escape/read_ssh_key.rs"]
mod read_ssh_key;

#[path = "../../../tests/escape/read_aws_credentials.rs"]
mod read_aws_credentials;

#[path = "../../../tests/escape/symlink_to_secret.rs"]
mod symlink_to_secret;

#[path = "../../../tests/escape/parent_dir_traversal.rs"]
mod parent_dir_traversal;

#[path = "../../../tests/escape/python_child_read.rs"]
mod python_child_read;

#[path = "../../../tests/escape/bash_child_read.rs"]
mod bash_child_read;

#[path = "../../../tests/escape/npm_script_read.rs"]
mod npm_script_read;

#[path = "../../../tests/escape/cargo_build_script_read.rs"]
mod cargo_build_script_read;

#[path = "../../../tests/escape/write_outside_repo.rs"]
mod write_outside_repo;
