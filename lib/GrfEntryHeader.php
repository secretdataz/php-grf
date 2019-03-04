<?php
/**
 * MIT License
 * 
 * Copyright (c) 2019 Carlos Henrique
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

class GrfEntryHeader
{
    /**
     * Gets the grf father about this entry
     * 
     * @return GrfFile
     */
    private $grf;

    /**
     * Entry file name
     * 
     * @var string
     */
    private $filename;

    /**
     * Compressed size entry
     * 
     * @return int
     */
    private $compressedSize;

    /**
     * Compressed size aligned
     * 
     * @return int
     */
    private $compressedSizeAligned;

    /**
     * Uncompressed size for entry
     * 
     * @return int
     */
    private $unCompressedSize;

    /**
     * Flags (?)
     * 
     * @return int
     */
    private $flags;

    /**
     * Offset position in grf file.
     * 
     * @return int
     */
    private $offset;

    /**
     * Header length.
     * @return int
     */
    private $size;

    /**
     * File bytes compressed state
     * 
     * @var string
     */
    private $compressedBytes;

    /**
     * The cycle for reading file.
     * 
     * @var string
     */
    private $cycle;

    /**
     * Reads the buffer and populates the file entries
     * 
     * @param string       $name      Filename
     * @param BufferReader $buffer    Bytes to populate the header entry
     * @param GrfFile      $grf       The grf file who handles this file
     * @param string       $fileBytes File bytes content
     * 
     * @return void
     */
    public function __construct($name, BufferReader $buffer = null, GrfFile $grf, $fileBytes = null)
    {
        $this->grf = $grf;
        $this->filename = utf8_encode($name);
        $this->cycle = -1;

        if ($fileBytes === null) {
            $this->compressedSize = $buffer->getUInt32();
            $this->compressedSizeAligned = $buffer->getUInt32();
            $this->unCompressedSize = $buffer->getUInt32();
            $this->flags = $buffer->getUInt8();
            $this->offset = $buffer->getUInt32() + GrfFile::GRF_HEADER_SIZE;

            if ($this->flags & self::GRF_FLAG_MIXCRYPT) {
                $this->cycle = 1;
                for ($i = 10; $this->compressedSize >= $i; $i *= 10)
                    $this->cycle++;
            }

            if ($this->flags & self::GRF_FLAG_DES) {
                $this->cycle = 0;
            }

            return;
        }

        // New files must to calculate they position
        $this->compressedBytes = $this->grf->compress($fileBytes);
        $this->compressedSize = strlen($this->compressedBytes);
        $this->compressedSizeAligned = $this->compressedSize + (4 - (($this->compressedSize - 1) % 4)) - 1;
        $this->unCompressedSize = strlen($fileBytes);
        $this->flags = self::GRF_FLAG_FILE;
        $this->offset = -1;
    }

    /**
     * Remove the file from entries collections
     * 
     * @return void
     */
    public function delete()
    {
        $this->getGrf()->delete($this->getFilename());
    }

    /**
     * Gets the hash for the file
     * 
     * @param string $algo Algorithm that'll hash the files
     * 
     * @return string
     */
    public function getHash($algo = 'md5')
    {
        $buffer = $this->getCompressedBuffer();
        $hash = hash($algo, $buffer);
        unset ($buffer);
        return $hash;
    }

    /**
     * Fetches the uncompressed buffer for this entry in grf file
     * 
     * @return string
     */
    public function getUnCompressedBuffer()
    {
        return $this->grf->decompress($this->getCompressedBuffer());
    }

    /**
     * Fetchs the compressed buffer for this entry in grf file
     * 
     * @return string
     */
    public function getCompressedBuffer()
    {
        // Not a file? Can't get the buffer...
        if (($this->getFlags() & self::GRF_FLAG_FILE) == 0)
            return null;

        if ($this->compressedBytes === null) {
            // FIXED: Needs to use the compressed aligned for encrypted files.
            $this->compressedBytes = $this->getGrf()->readBuffer($this->getOffset(), $this->getCompressedSizeAligned());

            if ($this->getCycle() >= 0) {
                // Decrypt/decodes the compressed bytes and store it in memory
                // @TODO: Decode functions goes here
            }

            // Fetches the compressed buffer again
            return $this->getCompressedBuffer();
        }

        // Return the compressed buffer data
        return $this->compressedBytes;
    }

    /**
     * Returns the grf father for this entry
     * 
     * @return GrfFile
     */
    public function getGrf()
    {
        return $this->grf;
    }

    /**
     * Gets the offset position file in grf
     * 
     * @return int
     */
    public function getOffset()
    {
        return $this->offset;
    }

    /**
     * Get the flag for entry
     * 
     * @return int
     */
    public function getFlags()
    {
        return $this->flags;
    }

    /**
     * Gets the uncompressed size for the entry
     * 
     * @return int
     */
    public function getUnCompressedSize()
    {
        return $this->unCompressedSize;
    }

    /**
     * Gets the compressed size aligned for the entry
     * 
     * @return int
     */
    public function getCompressedSizeAligned()
    {
        return $this->compressedSizeAligned;
    }

    /**
     * Gets the compressed size for the entry
     * 
     * @return int
     */
    public function getCompressedSize()
    {
        return $this->compressedSize;
    }

    /**
     * Gets entry file name
     * 
     * @return string
     */
    public function getFilename()
    {
        return $this->filename;
    }

    /**
     * Gets the cycle from grf flag.
     * 
     * @return int
     */
    public function getCycle()
    {
        return $this->cycle;
    }

    /**
     * Makes the swap using nibble data
     * 
     * @param string $src The string to do the swap
     * @param int    $len The length to do the swap
     * 
     * @return string
     */
    private function nibbleSwap($src, $len)
    {
        $tmpSrc = str_split($src);

        for ($i = 0; $i < $len; $i++) {
            $chr = ord($tmpSrc[$i]);
            $tmpSrc[$i] = ($chr >> 4 | $chr << 4);
        }

        return implode('', $tmpSrc);
    }

    /**
     * Values for encrypted grf (v0x102/0x103)
     * 
     * @var array
     */
    private $bitMaskTable = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01];

    /**
     * Bit swap table one
     * 
     * @var array
     */
    private $bitSwapTableOne = [58, 50, 42, 34, 26, 18, 10,  2, 60, 52, 44, 36, 28, 20, 12,  4,
                                62, 54, 46, 38, 30, 22, 14,  6, 64, 56, 48, 40, 32, 24, 16,  8,
                                57, 49, 41, 33, 25, 17,  9,  1, 59, 51, 43, 35, 27, 19, 11,  3,
                                61, 53, 45, 37, 29, 21, 13,  5, 63, 55, 47, 39, 31, 23, 15,  7];

    /**
     * Bit swap table two
     * 
     * @var array
     */
    private $bitSwapTableTwo = [40,  8, 48, 16, 56, 24, 64, 32, 39,  7, 47, 15, 55, 23, 63, 31,
                                38,  6, 46, 14, 54, 22, 62, 30, 37,  5, 45, 13, 53, 21, 61, 29,
                                36,  4, 44, 12, 52, 20, 60, 28, 35,  3, 43, 11, 51, 19, 59, 27,
                                34,  2, 42, 10, 50, 18, 58, 26, 33,  1, 41,  9, 49, 17, 57, 25];

    /**
     * Bit swap table three
     * 
     * @var array
     */
    private $bitSwapTableThree = [16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
                                   2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25];

    /**
     * Nibble data.
     * 
     * @var array
     */
    private $nibbleData = [
        [0xef, 0x03, 0x41, 0xfd, 0xd8, 0x74, 0x1e, 0x47,  0x26, 0xef, 0xfb, 0x22, 0xb3, 0xd8, 0x84, 0x1e,
        0x39, 0xac, 0xa7, 0x60, 0x62, 0xc1, 0xcd, 0xba,  0x5c, 0x96, 0x90, 0x59, 0x05, 0x3b, 0x7a, 0x85,
        0x40, 0xfd, 0x1e, 0xc8, 0xe7, 0x8a, 0x8b, 0x21,  0xda, 0x43, 0x64, 0x9f, 0x2d, 0x14, 0xb1, 0x72,
        0xf5, 0x5b, 0xc8, 0xb6, 0x9c, 0x37, 0x76, 0xec,  0x39, 0xa0, 0xa3, 0x05, 0x52, 0x6e, 0x0f, 0xd9],

        [0xa7, 0xdd, 0x0d, 0x78, 0x9e, 0x0b, 0xe3, 0x95,  0x60, 0x36, 0x36, 0x4f, 0xf9, 0x60, 0x5a, 0xa3,
        0x11, 0x24, 0xd2, 0x87, 0xc8, 0x52, 0x75, 0xec,  0xbb, 0xc1, 0x4c, 0xba, 0x24, 0xfe, 0x8f, 0x19,
        0xda, 0x13, 0x66, 0xaf, 0x49, 0xd0, 0x90, 0x06,  0x8c, 0x6a, 0xfb, 0x91, 0x37, 0x8d, 0x0d, 0x78,
        0xbf, 0x49, 0x11, 0xf4, 0x23, 0xe5, 0xce, 0x3b,  0x55, 0xbc, 0xa2, 0x57, 0xe8, 0x22, 0x74, 0xce],

        [0x2c, 0xea, 0xc1, 0xbf, 0x4a, 0x24, 0x1f, 0xc2,  0x79, 0x47, 0xa2, 0x7c, 0xb6, 0xd9, 0x68, 0x15,
        0x80, 0x56, 0x5d, 0x01, 0x33, 0xfd, 0xf4, 0xae,  0xde, 0x30, 0x07, 0x9b, 0xe5, 0x83, 0x9b, 0x68,
        0x49, 0xb4, 0x2e, 0x83, 0x1f, 0xc2, 0xb5, 0x7c,  0xa2, 0x19, 0xd8, 0xe5, 0x7c, 0x2f, 0x83, 0xda,
        0xf7, 0x6b, 0x90, 0xfe, 0xc4, 0x01, 0x5a, 0x97,  0x61, 0xa6, 0x3d, 0x40, 0x0b, 0x58, 0xe6, 0x3d],

        [0x4d, 0xd1, 0xb2, 0x0f, 0x28, 0xbd, 0xe4, 0x78,  0xf6, 0x4a, 0x0f, 0x93, 0x8b, 0x17, 0xd1, 0xa4,
        0x3a, 0xec, 0xc9, 0x35, 0x93, 0x56, 0x7e, 0xcb,  0x55, 0x20, 0xa0, 0xfe, 0x6c, 0x89, 0x17, 0x62,
        0x17, 0x62, 0x4b, 0xb1, 0xb4, 0xde, 0xd1, 0x87,  0xc9, 0x14, 0x3c, 0x4a, 0x7e, 0xa8, 0xe2, 0x7d,
        0xa0, 0x9f, 0xf6, 0x5c, 0x6a, 0x09, 0x8d, 0xf0,  0x0f, 0xe3, 0x53, 0x25, 0x95, 0x36, 0x28, 0xcb]
    ];

    // https://github.com/carloshenrq/grf/blob/master/includes/libgrf.h#L72-L75
    const GRF_FLAG_FILE = 0x1;
    const GRF_FLAG_MIXCRYPT = 0x2;
    const GRF_FLAG_DES = 0x4;

    // https://github.com/carloshenrq/grf/blob/master/includes/libgrf.h#L76-L77
    const GRF_FLAG_DELETE = 0x8;
}
