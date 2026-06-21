//! EntityData — a Godot Resource wrapping an entity's type, data, and hash.

use godot::prelude::*;

/// A Godot Resource representing an Entity Core entity.
///
/// Wraps the entity type string, raw CBOR data bytes, and content hash.
#[derive(GodotClass)]
#[class(base=Resource)]
pub struct EntityData {
    base: Base<Resource>,

    #[export]
    entity_type: GString,

    #[export]
    data: PackedByteArray,

    #[export]
    content_hash: PackedByteArray,
}

#[godot_api]
impl IResource for EntityData {
    fn init(base: Base<Resource>) -> Self {
        Self {
            base,
            entity_type: GString::new(),
            data: PackedByteArray::new(),
            content_hash: PackedByteArray::new(),
        }
    }
}

#[godot_api]
impl EntityData {
    /// Validate that the content hash matches the entity type and data.
    #[func]
    fn validate(&self) -> bool {
        let hash_bytes = self.content_hash.to_vec();
        if hash_bytes.len() != 33 {
            return false;
        }
        let claimed = match entity_hash::Hash::from_bytes(&hash_bytes) {
            Ok(h) => h,
            Err(_) => return false,
        };
        entity_hash::Hash::validate(
            &self.entity_type.to_string(),
            &self.data.to_vec(),
            &claimed,
        )
        .is_ok()
    }
}

impl EntityData {
    /// Create an EntityData from an entity_entity::Entity.
    pub fn from_entity(entity: &entity_entity::Entity) -> Gd<Self> {
        let mut data_bytes = PackedByteArray::new();
        data_bytes.extend(entity.data.iter().copied());

        let hash_bytes_arr = entity.content_hash.to_bytes();
        let mut hash_bytes = PackedByteArray::new();
        hash_bytes.extend(hash_bytes_arr.iter().copied());

        Gd::from_init_fn(|base| Self {
            base,
            entity_type: GString::from(entity.entity_type.as_str()),
            data: data_bytes,
            content_hash: hash_bytes,
        })
    }

    /// Rebuild an `entity_entity::Entity` from this EntityData. Used by
    /// binding methods that need to pass an Entity back into the SDK
    /// (e.g. `bundle_cross_peer_chain(leaf_cap)`).
    pub fn to_entity(&self) -> Result<entity_entity::Entity, entity_entity::EntityError> {
        entity_entity::Entity::new(&self.entity_type.to_string(), self.data.to_vec())
    }
}
