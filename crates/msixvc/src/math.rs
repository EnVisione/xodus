use crate::models::xvd::{
    BLOCK_SIZE, DATA_BLOCKS_IN_LEVEL0_HASHTREE, DATA_BLOCKS_IN_LEVEL1_HASHTREE,
    DATA_BLOCKS_IN_LEVEL2_HASHTREE, DATA_BLOCKS_IN_LEVEL3_HASHTREE, HASH_ENTRIES_IN_PAGE,
    LEGACY_SECTOR_SIZE, PAGE_SIZE, PAGES_PER_BLOCK, SECTOR_SIZE,
};
use thiserror::Error;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ArithmeticError {
    #[error("xvd {operation} overflows for value {value}")]
    ValueOverflow { operation: &'static str, value: u64 },
    #[error("xvd {operation} overflows for {left} and {right}")]
    BinaryOverflow {
        operation: &'static str,
        left: u64,
        right: u64,
    },
    #[error("xvd hash tree level {hash_level} is unsupported")]
    UnsupportedHashLevel { hash_level: u64 },
    #[error("xvd hash tree depth {hash_tree_levels} is invalid for hash level {hash_level}")]
    InvalidHashTreeDepth {
        hash_tree_levels: u64,
        hash_level: u32,
    },
    #[error("xvd type {xvd_type} is unsupported")]
    UnsupportedXvdType { xvd_type: u32 },
}

pub fn bytes_to_pages(bytes: u64) -> u64 {
    bytes.div_ceil(PAGE_SIZE as u64)
}

pub fn offset_to_block_number(offset: u64) -> u64 {
    offset / BLOCK_SIZE as u64
}

pub fn offset_to_page_number(offset: u64) -> u64 {
    offset / PAGE_SIZE as u64
}

pub fn checked_sectors_to_bytes(sectors: u64) -> Result<u64, ArithmeticError> {
    sectors
        .checked_mul(SECTOR_SIZE as u64)
        .ok_or(ArithmeticError::BinaryOverflow {
            operation: "sector to byte conversion",
            left: sectors,
            right: SECTOR_SIZE as u64,
        })
}

pub fn checked_legacy_sectors_to_bytes(sectors: u64) -> Result<u64, ArithmeticError> {
    sectors
        .checked_mul(LEGACY_SECTOR_SIZE as u64)
        .ok_or(ArithmeticError::BinaryOverflow {
            operation: "legacy sector to byte conversion",
            left: sectors,
            right: LEGACY_SECTOR_SIZE as u64,
        })
}

pub fn checked_page_number_to_offset(page_number: u64) -> Result<u64, ArithmeticError> {
    page_number
        .checked_mul(PAGE_SIZE as u64)
        .ok_or(ArithmeticError::BinaryOverflow {
            operation: "page to byte offset conversion",
            left: page_number,
            right: PAGE_SIZE as u64,
        })
}

pub fn calculate_hash_block_num_and_run_for_block_num(
    xvd_type: u32,
    hash_tree_levels: u64,
    number_of_hashed_pages: u64,
    block_num: u64,
    hash_level: u32,
    resilient: bool,
    unknown: bool,
) -> Result<(u64, u64, u64), ArithmeticError> {
    fn hash_block_exponent(block_count: u32) -> Result<u64, ArithmeticError> {
        (PAGES_PER_BLOCK as u64)
            .checked_pow(block_count)
            .ok_or(ArithmeticError::ValueOverflow {
                operation: "hash block exponent",
                value: u64::from(block_count),
            })
    }

    if xvd_type > 1 {
        return Err(ArithmeticError::UnsupportedXvdType { xvd_type });
    }
    if hash_level > 3 {
        return Err(ArithmeticError::UnsupportedHashLevel {
            hash_level: u64::from(hash_level),
        });
    }

    let entry_num_in_block =
        (block_num / hash_block_exponent(hash_level)?) % PAGES_PER_BLOCK as u64;
    let run_length = PAGES_PER_BLOCK as u64 - entry_num_in_block;

    if hash_level == 3 {
        return Ok((0, entry_num_in_block, run_length));
    }

    let mut result = block_num / hash_block_exponent(hash_level + 1)?;
    let mut remaining_hash_tree_levels = hash_tree_levels
        .checked_sub(u64::from(hash_level + 1))
        .ok_or(ArithmeticError::InvalidHashTreeDepth {
            hash_tree_levels,
            hash_level,
        })?;

    if hash_level == 0 && remaining_hash_tree_levels > 0 {
        let additional = number_of_hashed_pages.div_ceil(hash_block_exponent(2)?);
        result = result
            .checked_add(additional)
            .ok_or(ArithmeticError::BinaryOverflow {
                operation: "hash block number calculation",
                left: result,
                right: additional,
            })?;
        remaining_hash_tree_levels -= 1;
    }

    if (hash_level == 0 || hash_level == 1) && remaining_hash_tree_levels > 0 {
        let additional = number_of_hashed_pages.div_ceil(hash_block_exponent(3)?);
        result = result
            .checked_add(additional)
            .ok_or(ArithmeticError::BinaryOverflow {
                operation: "hash block number calculation",
                left: result,
                right: additional,
            })?;
        remaining_hash_tree_levels -= 1;
    }

    if remaining_hash_tree_levels > 0 {
        let additional = number_of_hashed_pages.div_ceil(hash_block_exponent(4)?);
        result = result
            .checked_add(additional)
            .ok_or(ArithmeticError::BinaryOverflow {
                operation: "hash block number calculation",
                left: result,
                right: additional,
            })?;
    }

    if resilient {
        result = result
            .checked_mul(2)
            .ok_or(ArithmeticError::BinaryOverflow {
                operation: "resilient hash block number calculation",
                left: result,
                right: 2,
            })?;
    }

    if unknown {
        result = result
            .checked_add(1)
            .ok_or(ArithmeticError::BinaryOverflow {
                operation: "unknown hash block number calculation",
                left: result,
                right: 1,
            })?;
    }

    Ok((result, entry_num_in_block, run_length))
}

pub fn calculate_number_of_hash_blocks_in_level(
    size: u64,
    hash_level: u64,
    resilient: bool,
) -> Result<u64, ArithmeticError> {
    let hash_blocks = match hash_level {
        0 => size.div_ceil(DATA_BLOCKS_IN_LEVEL0_HASHTREE as u64),
        1 => size.div_ceil(DATA_BLOCKS_IN_LEVEL1_HASHTREE as u64),
        2 => size.div_ceil(DATA_BLOCKS_IN_LEVEL2_HASHTREE as u64),
        3 => size.div_ceil(DATA_BLOCKS_IN_LEVEL3_HASHTREE as u64),
        _ => {
            return Err(ArithmeticError::UnsupportedHashLevel { hash_level });
        }
    };

    if resilient {
        return hash_blocks
            .checked_mul(2)
            .ok_or(ArithmeticError::BinaryOverflow {
                operation: "resilient hash block count calculation",
                left: hash_blocks,
                right: 2,
            });
    }

    Ok(hash_blocks)
}

pub fn calculate_number_of_hash_pages(
    hashed_pages_count: u64,
    resilient: bool,
) -> Result<(u64, u64), ArithmeticError> {
    let mut hash_tree_levels = 1;
    let mut hash_tree_pages = hashed_pages_count.div_ceil(HASH_ENTRIES_IN_PAGE as u64);
    if hash_tree_pages > 1 {
        let mut result = 2;
        while result > 1 {
            result = calculate_number_of_hash_blocks_in_level(
                hashed_pages_count,
                hash_tree_levels,
                false,
            )?;
            hash_tree_levels =
                hash_tree_levels
                    .checked_add(1)
                    .ok_or(ArithmeticError::ValueOverflow {
                        operation: "hash tree level count",
                        value: hash_tree_levels,
                    })?;
            hash_tree_pages =
                hash_tree_pages
                    .checked_add(result)
                    .ok_or(ArithmeticError::BinaryOverflow {
                        operation: "hash tree page count",
                        left: hash_tree_pages,
                        right: result,
                    })?;
        }
    }

    if resilient {
        hash_tree_pages =
            hash_tree_pages
                .checked_mul(2)
                .ok_or(ArithmeticError::BinaryOverflow {
                    operation: "resilient hash tree page count",
                    left: hash_tree_pages,
                    right: 2,
                })?;
    }

    Ok((hash_tree_levels, hash_tree_pages))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_page_offset_rejects_multiplication_overflow() {
        assert!(matches!(
            checked_page_number_to_offset(u64::MAX),
            Err(ArithmeticError::BinaryOverflow {
                operation: "page to byte offset conversion",
                ..
            })
        ));
    }

    #[test]
    fn checked_sector_conversions_preserve_valid_values() {
        assert_eq!(checked_sectors_to_bytes(2).unwrap(), 2 * SECTOR_SIZE as u64);
        assert_eq!(
            checked_legacy_sectors_to_bytes(2).unwrap(),
            2 * LEGACY_SECTOR_SIZE as u64
        );
    }

    #[test]
    fn checked_sector_conversion_rejects_multiplication_overflow() {
        assert!(matches!(
            checked_sectors_to_bytes(u64::MAX),
            Err(ArithmeticError::BinaryOverflow {
                operation: "sector to byte conversion",
                ..
            })
        ));
    }

    #[test]
    fn hash_block_calculation_rejects_depth_underflow() {
        assert!(matches!(
            calculate_hash_block_num_and_run_for_block_num(0, 0, 1, 0, 0, false, false),
            Err(ArithmeticError::InvalidHashTreeDepth {
                hash_tree_levels: 0,
                hash_level: 0,
            })
        ));
    }

    #[test]
    fn hash_page_calculation_rejects_unsupported_depth_instead_of_panicking() {
        assert!(matches!(
            calculate_number_of_hash_pages(u64::MAX, false),
            Err(ArithmeticError::UnsupportedHashLevel { hash_level: 4 })
        ));
    }
}
