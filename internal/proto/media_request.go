package proto

import "time"

type InitMediaUploadRequest struct {
	SHA256     []byte `json:"sha256"`
	SizeBytes  int64  `json:"size_bytes"`
	MimeType   string `json:"mime_type"`
	TTLSeconds int64  `json:"ttl_seconds,omitempty"`

	// AuthorizedAccountIDs OPTIONALLY declares the conversation audience allowed
	// to download this object (in addition to the uploader). When set, download
	// is enforced to that set; when omitted (older clients), the object stays
	// readable by any authenticated caller — see media.Service for the gap note.
	// Additive + backward compatible: existing clients simply don't send it.
	AuthorizedAccountIDs []string `json:"authorized_account_ids,omitempty"`

	// ServerUpload asks for the ciphertext to be uploaded THROUGH this server
	// (POST /media/upload?media_id=...) instead of straight to S3 with a
	// presigned URL. A browser cannot use the presigned URL (cross-origin, no
	// CORS on the bucket), so the web client sets it. Additive: native clients
	// don't send it and keep the presigned PUT.
	ServerUpload bool `json:"server_upload,omitempty"`
}

type InitMediaUploadResponse struct {
	MediaID      string    `json:"media_id"`
	UploadURL    string    `json:"upload_url"`
	UploadExpiry time.Time `json:"upload_expiry"`
}

type GetMediaRequest struct {
	MediaID string `json:"media_id"`
}

type GetMediaResponse struct {
	DownloadURL    string    `json:"download_url"`
	DownloadExpiry time.Time `json:"download_expiry"`
	MimeType       string    `json:"mime_type"`
	SizeBytes      int64     `json:"size_bytes"`
}

// MediaRecord is the persisted media metadata.
type MediaRecord struct {
	MediaID           string
	UploaderAccountID string
	UploaderDeviceID  string
	SHA256            []byte
	SizeBytes         int64
	MimeType          string
	ObjectKey         string
	UploadedAt        time.Time
	ExpiresAt         time.Time
	DeletedAt         *time.Time

	// AuthorizedAccountIDs is the download allow-list (empty/nil = legacy open
	// access to any authenticated caller). The uploader is always allowed
	// regardless of this list.
	AuthorizedAccountIDs []string
}
