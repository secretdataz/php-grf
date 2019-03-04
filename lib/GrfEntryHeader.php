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

    // https://github.com/carloshenrq/grf/blob/master/includes/libgrf.h#L72-L75
    const GRF_FLAG_FILE = 0x1;
    const GRF_FLAG_MIXCRYPT = 0x2;
    const GRF_FLAG_DES = 0x4;

    // https://github.com/carloshenrq/grf/blob/master/includes/libgrf.h#L76-L77
    const GRF_FLAG_DELETE = 0x8;
}
