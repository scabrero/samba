/*
 * Copyright (C) Samuel Cabrero 2021
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include "replace.h"
#include "lzhuff_xpress.h"
#include "../lib/util/byteorder.h"
#include "lib/util/tsort.h"

#define __BUF_POS_CONST(buf,ofs)(((const uint8_t *)buf)+(ofs))
#define __PULL_BYTE(buf,ofs) \
	((uint8_t)((*__BUF_POS_CONST(buf,ofs)) & 0xFF))

#ifndef PULL_LE_UINT16
#define PULL_LE_UINT16(buf,ofs) ((uint16_t)( \
	((uint16_t)(((uint16_t)(__PULL_BYTE(buf,(ofs)+0))) << 0)) | \
	((uint16_t)(((uint16_t)(__PULL_BYTE(buf,(ofs)+1))) << 8)) \
))
#endif

/**
 * Represents a node in a Huffman prefix code tree
 */
struct prefix_code_node {
	/* Stores the symbol encoded by this node in the prefix code tree */
	uint16_t symbol;

	/* Indicates whether this node is a leaf in the tree */
	bool leaf;

	/* Points to the node’s two children. The value NIL is used to
	 * indicate that a particular child does not exist */
	struct prefix_code_node *child[2];
};

/**
 * Represent information about a Huffman-encoded symbol
 */
struct prefix_code_symbol {
	/* Stores the symbol */
	uint16_t symbol;

	/* Stores the symbol’s Huffman prefix code length */
	uint16_t length;
};

/**
 * Represent a byte array as a bit string from which individual bits can
 * be read
 */
struct bitstring {
	/* The byte array */
	const uint8_t *source;

	/* The index in source from which the next set of bits will be pulled
         * when the bits in mask have been consumed */
	uint32_t index;

	/* Stores the next bits to be consumed in the bit string */
	uint32_t mask;

	/* Stores the number of bits in mask that remain to be consumed */
	int32_t bits;
};

/**
 * Links a symbol's prefix_code_node into its correct position in a Huffman
 * prefix code tree
 */
static uint32_t prefix_code_tree_add_leaf(struct prefix_code_node *tree_nodes,
					uint32_t leaf_index,
					uint32_t mask,
					uint32_t bits)
{
	struct prefix_code_node *node = &tree_nodes[0];
	uint32_t i = leaf_index + 1;
	uint32_t child_index;

	while (bits > 1) {
		bits = bits - 1;
		child_index = (mask >> bits) & 1;
		if (node->child[child_index] == NULL) {
			node->child[child_index] = &tree_nodes[i];
			tree_nodes[i].leaf = false;
			i = i + 1;
		}
		node = node->child[child_index];
	}

	node->child[mask & 1] = &tree_nodes[leaf_index];

	return i;
}

/**
 * Determines the sort order of one prefix_code_symbol relative to another
 */
static int compare_symbols(struct prefix_code_symbol *e1,
			struct prefix_code_symbol *e2)
{
	if (e1->length < e2->length)
		return -1;
	else if (e1->length > e2->length)
		return 1;
	else if (e1->symbol < e2->symbol)
		return -1;
	else if (e1->symbol > e2->symbol)
		return 1;
	else
		return 0;
}

/**
 * Rebuilds the Huffman prefix code tree that will be used to decode symbols
 * during decompression
 */
static struct prefix_code_node *PrefixCodeTreeRebuild(const uint8_t *input,
				struct prefix_code_node *tree_nodes)
{
	struct prefix_code_node *root;
	struct prefix_code_symbol symbolInfo[512];
	uint32_t i, j, mask, bits;

	for (i = 0; i < 1024; i++) {
		tree_nodes[i].symbol = 0;
		tree_nodes[i].leaf = false;
		tree_nodes[i].child[0] = NULL;
		tree_nodes[i].child[1] = NULL;
	}

	for (i = 0; i < 256; i++) {
		symbolInfo[2*i].symbol = 2*i;
		symbolInfo[2*i].length = input[i] & 15;
		symbolInfo[2*i+1].symbol = 2*i+1;
		symbolInfo[2*i+1].length = input[i] >> 4;
	}

	TYPESAFE_QSORT(symbolInfo, 512, compare_symbols);

	i = 0;
	while (i < 512 && symbolInfo[i].length == 0) {
		i = i + 1;
	}

	mask = 0;
	bits = 1;

	root = &tree_nodes[0];
	root->leaf = false;

	j = 1;
	for (; i < 512; i++) {
		tree_nodes[j].symbol = symbolInfo[i].symbol;
		tree_nodes[j].leaf = true;
		mask <<= symbolInfo[i].length - bits;
		bits = symbolInfo[i].length;
		j = prefix_code_tree_add_leaf(tree_nodes, j, mask, bits);
		mask += 1;
	}

	return root;
}

/**
 * Initializes a bitstream data structure
 */
static void bitstring_init(struct bitstring *bstr,
			const uint8_t *source,
			uint32_t index)
{
	bstr->mask = PULL_LE_UINT16(source, index);
	bstr->mask <<= sizeof(bstr->mask) * 8 - 16;
	index += 2;

	bstr->mask += PULL_LE_UINT16(source, index);
	index += 2;

	bstr->bits = 32;
	bstr->source = source;
	bstr->index = index;
}

/**
 * Returns the next n bits from the front of a bit string.
 */
static uint32_t bitstring_lookup(struct bitstring *bstr, uint32_t n)
{
	if (n == 0) {
		return 0;
	}
	return bstr->mask >> (sizeof(bstr->mask) * 8 - n);
}

/**
 * Advances the bit string's cursor by n bits.
 */
static void bitstring_skip(struct bitstring *bstr, uint32_t n)
{
	bstr->mask = bstr->mask << n;
	bstr->bits = bstr->bits - n;

	if (bstr->bits < 16) {
		bstr->mask += PULL_LE_UINT16(bstr->source, bstr->index) <<
				(16 - bstr->bits);
		bstr->index = bstr->index + 2;
		bstr->bits = bstr->bits + 16;
	}
}

/**
 * Returns the symbol encoded by the next prefix code in a bit string.
 */
static uint32_t prefix_code_tree_decode_symbol(struct bitstring *bstr,
					 struct prefix_code_node *root)
{
	uint32_t bit;
	struct prefix_code_node *node = root;

	do {
		bit = bitstring_lookup(bstr, 1);
		bitstring_skip(bstr, 1);

		node = node->child[bit];
	} while (node->leaf == false);

	return node->symbol;
}

ssize_t lzhuff_xpress_decompress(const uint8_t *input,
				uint32_t input_size,
				uint8_t *output,
				uint32_t output_size)
{
	ssize_t i = 0;
	uint32_t stop_index = output_size;
	uint32_t symbol;
	uint32_t length;
	int32_t offset;
	struct prefix_code_node *root;
	struct prefix_code_node prefix_code_tree_nodes[1024];
	struct bitstring bstr;

	root = PrefixCodeTreeRebuild(input, prefix_code_tree_nodes);

	bitstring_init(&bstr, input, 256);

	while (i < stop_index) {
		symbol = prefix_code_tree_decode_symbol(&bstr, root);
		if (symbol < 256) {
			output[i] = symbol & 0xFF;
			i++;
		} else {
			symbol = symbol - 256;
			length = symbol & 0xF;
			symbol = symbol >> 4;

			offset = (1U << symbol) + bitstring_lookup(&bstr, symbol);
			offset *= -1;

			if (length == 15) {
				length = bstr.source[bstr.index] + 15;
				bstr.index += 1;

				if (length == 270) {
					length = PULL_LE_UINT16(bstr.source, bstr.index);
					bstr.index += 2;
				}
			}

			bitstring_skip(&bstr, symbol);

			length += 3;
			do {
				output[i] = output[i + offset];
				i++;
				length--;
			} while (length != 0);
		}
	}

	return i;
}
