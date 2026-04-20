// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Write an object to the store.
//
// Object format on disk:
//   "<type> <size>\0<data>"
//   where <type> is "blob", "tree", or "commit"
//   and <size> is the decimal string of the data length
//
// Steps:
//   1. Build the full object: header ("blob 16\0") + data
//   2. Compute SHA-256 hash of the FULL object (header + data)
//   3. Check if object already exists (deduplication) — if so, just return success
//   4. Create shard directory (.pes/objects/XX/) if it doesn't exist
//   5. Write to a temporary file in the same shard directory
//   6. fsync() the temporary file to ensure data reaches disk
//   7. rename() the temp file to the final path (atomic on POSIX)
//   8. Open and fsync() the shard directory to persist the rename
//   9. Store the computed hash in *id_out

// HINTS - Useful syscalls and functions for this phase:
//   - sprintf / snprintf : formatting the header string
//   - compute_hash       : hashing the combined header + data
//   - object_exists      : checking for deduplication
//   - mkdir              : creating the shard directory (use mode 0755)
//   - open, write, close : creating and writing to the temp file
//                          (Use O_CREAT | O_WRONLY | O_TRUNC, mode 0644)
//   - fsync              : flushing the file descriptor to disk
//   - rename             : atomically moving the temp file to the final path
//

//
// Returns 0 on success, -1 on error.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {

    char header[64];
    const char *type_str;

    if (type == OBJ_BLOB) type_str = "blob";
    else if (type == OBJ_TREE) type_str = "tree";
    else type_str = "commit";

    int header_len = sprintf(header, "%s %zu", type_str, len);

    header[header_len] = '\0';
    header_len++;

    // ===== ADD FROM HERE (STEP 2) =====

    size_t total_len = header_len + len;
    unsigned char *full = malloc(total_len);

    memcpy(full, header, header_len);
    memcpy(full + header_len, data, len);

    ObjectID hash;
    compute_hash(full, total_len, &hash);

	// ===== ADD STEP 3 HERE =====

	char path[512];
	object_path(&hash, path, sizeof(path));

	// if object already exists, skip writing
	if (object_exists(&hash)) {
	    *id_out = hash;
	    free(full);
	    return 0;
	}
	
	// create shard directory
	char hex[HASH_HEX_SIZE + 1];
	hash_to_hex(&hash, hex);

	char dir[512];
	snprintf(dir, sizeof(dir), "%s/%.2s", OBJECTS_DIR, hex);
	mkdir(dir, 0755);
	
	// temp file path
	char temp_path[512];
	snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);

	// write to temp file
	int fd = open(temp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
	if (fd < 0) {
	    free(full);
	    return -1;
	}

	if ((size_t)write(fd, full, total_len) != total_len) {
	    close(fd);
	    free(full);
	    return -1;
	}
	fsync(fd);
	close(fd);	

	// rename temp file → final path
	if (rename(temp_path, path) != 0) {
	    free(full);
	    return -1;
	}

	// fsync the directory to persist rename
	int dir_fd = open(dir, O_RDONLY);
	if (dir_fd >= 0) {
	    fsync(dir_fd);
	    close(dir_fd);
	}	
	// set output hash	
	*id_out = hash;

	// cleanup
	free(full);

	return 0;

}

// Read an object from the store.
//
// Steps:
//   1. Build the file path from the hash using object_path()
//   2. Open and read the entire file
//   3. Parse the header to extract the type string and size
//   4. Verify integrity: recompute the SHA-256 of the file contents
//      and compare to the expected hash (from *id). Return -1 if mismatch.
//   5. Set *type_out to the parsed ObjectType
//   6. Allocate a buffer, copy the data portion (after the \0), set *data_out and *len_out
//
// HINTS - Useful syscalls and functions for this phase:
//   - object_path        : getting the target file path
//   - fopen, fread, fseek: reading the file into memory
//   - memchr             : safely finding the '\0' separating header and data
//   - strncmp            : parsing the type string ("blob", "tree", "commit")
//   - compute_hash       : re-hashing the read data for integrity verification
//   - memcmp             : comparing the computed hash against the requested hash
//   - malloc, memcpy     : allocating and returning the extracted data
//
// The caller is responsible for calling free(*data_out).
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).
int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    char path[512];
    object_path(id, path, sizeof(path));

    // 1. Open the file
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    // 2. Get file size to read the whole thing
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *buffer = malloc(file_size);
    if (fread(buffer, 1, file_size, f) != (size_t)file_size) {
        free(buffer);
        fclose(f);
        return -1;
    }
    fclose(f);

    // 3. Integrity Check: Recompute hash of what we just read
    ObjectID actual_hash;
    compute_hash(buffer, file_size, &actual_hash);
    if (memcmp(id->hash, actual_hash.hash, HASH_SIZE) != 0) {
        free(buffer);
        return -1; // Data corruption detected
    }

    // 4. Parse Header (Format: "<type> <size>\0<data>")
    // Find the null terminator that separates header from data
    char *null_ptr = memchr(buffer, '\0', file_size);
    if (!null_ptr) {
        free(buffer);
        return -1;
    }

    size_t header_len = (null_ptr - (char *)buffer) + 1;
    size_t data_len = file_size - header_len;

    // Determine type
    if (strncmp((char *)buffer, "blob", 4) == 0) *type_out = OBJ_BLOB;
    else if (strncmp((char *)buffer, "tree", 4) == 0) *type_out = OBJ_TREE;
    else if (strncmp((char *)buffer, "commit", 6) == 0) *type_out = OBJ_COMMIT;

    // 5. Allocate and return the data portion
    *data_out = malloc(data_len);
    memcpy(*data_out, buffer + header_len, data_len);
    *len_out = data_len;

    free(buffer);
    return 0;
}
