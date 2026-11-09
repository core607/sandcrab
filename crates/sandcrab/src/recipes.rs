//! Flat immutable recipes bind layer order without copying any published tree.
use crate::{file_records::Result, template_io::Tree};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::{io, path::Path};

pub const MAX_LAYERS: usize = 16;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub layers: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Recipe {
    pub id: String,
    pub uid: u32,
    pub gid: u32,
    pub layers: Vec<String>,
}

impl Recipe {
    pub fn new(layers: Vec<String>, trees: &BTreeMap<String, Tree>) -> Result<Self> {
        let id = identity(&layers)?;
        let first = trees
            .get(&layers[0])
            .ok_or((409, "TEMPLATE_LAYER_NOT_FOUND"))?;
        for id in &layers {
            let layer = trees.get(id).ok_or((409, "TEMPLATE_LAYER_NOT_FOUND"))?;
            if (layer.uid, layer.gid) != (first.uid, first.gid) {
                return Err((409, "TEMPLATE_IDENTITY_MISMATCH"));
            }
        }
        Ok(Self {
            id,
            uid: first.uid,
            gid: first.gid,
            layers,
        })
    }
}

pub fn identity(layers: &[String]) -> Result<String> {
    if layers.is_empty()
        || layers.len() > MAX_LAYERS
        || layers.iter().any(|id| !crate::file_io::digest(id))
        || layers.iter().collect::<BTreeSet<_>>().len() != layers.len()
    {
        return Err((400, "INVALID_RECIPE"));
    }
    let mut hash = Sha256::new();
    hash.update(b"sandcrab-template-recipe-v1\0");
    hash.update((layers.len() as u32).to_le_bytes());
    for id in layers {
        hash.update(id.as_bytes());
    }
    Ok(format!("{:x}", hash.finalize()))
}

pub fn read(path: &Path, trees: &BTreeMap<String, Tree>) -> io::Result<Recipe> {
    sandcrab_core::fs::protected_directory(path)?;
    crate::storage::no_mounts_below(path, false)?;
    let recipe: Recipe = serde_json::from_slice(&sandcrab_core::fs::protected_file(
        &path.join("record.json"),
        4096,
    )?)?;
    if path.file_name().and_then(|name| name.to_str()) != Some(recipe.id.as_str())
        || Recipe::new(recipe.layers.clone(), trees).ok().as_ref() != Some(&recipe)
        || trees.contains_key(&recipe.id)
    {
        return Err(crate::config::invalid(
            "Invalid template recipe or layer reference",
        ));
    }
    Ok(recipe)
}
