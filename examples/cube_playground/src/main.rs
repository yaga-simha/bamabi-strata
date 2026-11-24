#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Ultra-lean Bevy + [`StrataPlugin`] host.
//!
//! Rust sets the 60 Hz fixed timestep and mounts [`StrataPlugin`]; all geometry,
//! materials, lights, cameras, and 60 Hz behavior live in the `.strata` script.

mod strata_plugin;

use crate::strata_plugin::StrataPlugin;
use bevy::prelude::*;
use std::path::PathBuf;

fn main() {
    let script = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(StrataPlugin::default_script_path);

    App::new()
        .insert_resource(Time::<Fixed>::from_hz(60.0))
        .add_plugins(StrataPlugin::watch(script))
        .run();
}
