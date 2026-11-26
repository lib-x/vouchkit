use serde::{Deserialize, Deserializer, Serialize, de::Error};

use crate::LicenseError;

/// Maximum number of disjoint slot intervals per license or certificate.
pub const MAX_FEATURE_RANGES: usize = 16;

/// A compact authorization set over the product's 65,536 feature slots.
///
/// Each pair is inclusive. Adjacent or overlapping intervals are merged.
/// A grant of an entire module interval covers slots added to that interval later.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct FeatureSlots(Vec<(u16, u16)>);

impl FeatureSlots {
    /// Builds a set from individual slots and inclusive intervals.
    ///
    /// # Errors
    ///
    /// Rejects reversed intervals or more than [MAX_FEATURE_RANGES] disjoint intervals.
    pub fn try_from_ranges(ranges: &[(u16, u16)]) -> Result<Self, LicenseError> {
        let mut sorted = ranges.to_vec();
        sorted.sort_unstable();
        let mut merged: Vec<(u16, u16)> = Vec::new();
        for (start, end) in sorted {
            if start > end {
                return Err(LicenseError::Malformed);
            }
            if let Some((_, previous_end)) = merged.last_mut()
                && start <= previous_end.saturating_add(1)
            {
                *previous_end = (*previous_end).max(end);
            } else {
                if merged.len() == MAX_FEATURE_RANGES {
                    return Err(LicenseError::Malformed);
                }
                merged.push((start, end));
            }
        }
        Ok(Self(merged))
    }

    /// Returns the sorted, disjoint, inclusive intervals.
    pub fn ranges(&self) -> &[(u16, u16)] {
        &self.0
    }

    /// Checks whether the product-defined slot is authorized.
    pub fn contains(&self, slot: u16) -> bool {
        self.0
            .iter()
            .any(|&(start, end)| (start..=end).contains(&slot))
    }

    /// Checks whether all granted slots are also present in the other set.
    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.0.iter().all(|&(start, end)| {
            other
                .0
                .iter()
                .any(|&(floor, ceiling)| floor <= start && end <= ceiling)
        })
    }

    /// Returns whether the grant set is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<u32> for FeatureSlots {
    /// Converts bits 0 through 31 into their corresponding feature slots.
    fn from(mask: u32) -> Self {
        let mut ranges: Vec<(u16, u16)> = Vec::new();
        for slot in (0..32).filter(|slot| mask & (1 << slot) != 0) {
            if let Some((_, end)) = ranges.last_mut()
                && *end + 1 == slot
            {
                *end = slot;
            } else {
                ranges.push((slot, slot));
            }
        }
        Self(ranges)
    }
}

impl<'de> Deserialize<'de> for FeatureSlots {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let ranges = Vec::<(u16, u16)>::deserialize(deserializer)?;
        if ranges.len() > MAX_FEATURE_RANGES
            || ranges.iter().any(|(start, end)| start > end)
            || ranges.windows(2).any(|pair| match pair {
                [(_, left), (right, _)] => *right <= left.saturating_add(1),
                _ => false,
            })
        {
            return Err(D::Error::custom("invalid feature intervals"));
        }
        Ok(Self(ranges))
    }
}
