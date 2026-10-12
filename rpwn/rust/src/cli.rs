//! A faithful reimplementation of Python's `getopt.getopt` for the exact option table the
//! `rpwn` script uses.
//!
//! Behavioural details that are preserved because the original relies on them:
//!   * long options may be spelled with one or two leading dashes;
//!   * `--name=value` supplies the argument inline, otherwise the next argv element is used
//!     (even if it starts with `-`);
//!   * a non-option argument stops parsing;
//!   * a bare `--` terminates option parsing.
//!
//! Anything the original would reject raises `GetoptError`, which the caller turns into
//! "ERROR: Invalid arguments provided." plus exit status 2.

/// `(name, takes_argument)`
const LONG_OPTS: &[(&str, bool)] = &[
    ("demote", false),
    ("boot", false),
    ("dump", true),
    ("hexdump", true),
    ("dump-rom", false),
    ("dump-nor", true),
    ("flash-nor", true),
    ("dump-ace2", true),
    ("memory-map", false),
    ("24kpwn", false),
    ("remove-24kpwn", false),
    ("remove-alloc8", false),
    ("decrypt-gid", true),
    ("encrypt-gid", true),
    ("decrypt-uid", true),
    ("encrypt-uid", true),
    ("goat-run", true),
    ("goat-write", true),
    ("detect", false),
    ("reach", false),
];

/// The `shortopts` string `getopt` was called with is `'pxf:'`.
const SHORT_OPTS: &[(char, bool)] = &[('p', false), ('x', false), ('f', true)];

pub fn getopt(args: &[String]) -> Result<Vec<(String, String)>, String> {
    let mut opts: Vec<(String, String)> = Vec::new();

    // `getopt` treats a leading `--` as an end-of-options marker.
    if args.first().map(|s| s.as_str()) == Some("--") {
        return Ok(opts);
    }

    let mut index = 0usize;
    while index < args.len() {
        let arg = args[index].clone();

        if let Some(body) = arg.strip_prefix("--") {
            if body.is_empty() {
                break;
            }
            let (name, inline) = match body.split_once('=') {
                Some((name, value)) => (name, Some(value.to_string())),
                None => (body, None),
            };

            let (_, takes_argument) = LONG_OPTS
                .iter()
                .find(|(candidate, _)| *candidate == name)
                .ok_or_else(|| format!("option --{} not recognized", name))?;

            let value = if *takes_argument {
                match inline {
                    Some(value) => value,
                    None => {
                        index += 1;
                        args.get(index)
                            .cloned()
                            .ok_or_else(|| format!("option --{} requires argument", name))?
                    }
                }
            } else {
                if inline.is_some() {
                    return Err(format!("option --{} must not have an argument", name));
                }
                String::new()
            };

            opts.push((format!("--{}", name), value));
            index += 1;
            continue;
        }

        if arg.starts_with('-') && arg.len() > 1 {
            let chars: Vec<char> = arg.chars().skip(1).collect();
            let mut position = 0usize;
            while position < chars.len() {
                let flag = chars[position];
                let (_, takes_argument) = SHORT_OPTS
                    .iter()
                    .find(|(candidate, _)| *candidate == flag)
                    .ok_or_else(|| format!("option -{} not recognized", flag))?;

                if *takes_argument {
                    let inline: String = chars[position + 1..].iter().collect();
                    let value = if inline.is_empty() {
                        index += 1;
                        args.get(index)
                            .cloned()
                            .ok_or_else(|| format!("option -{} requires argument", flag))?
                    } else {
                        inline
                    };
                    opts.push((format!("-{}", flag), value));
                    // The rest of this token was consumed as the argument, so there are
                    // no further flags to read from it.
                    break;
                }
                opts.push((format!("-{}", flag), String::new()));
                position += 1;
            }
            index += 1;
            continue;
        }

        // First non-option argument: the rest of the command line is left alone.
        break;
    }

    Ok(opts)
}
