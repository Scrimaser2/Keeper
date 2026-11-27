package catalog

import (
	"path/filepath"
	"strings"
)

type Category string

const (
	Visual   Category = "Визуальное"
	Video    Category = "Видео"
	Text     Category = "Текст"
	Document Category = "Документы"
	Other    Category = "Другое"
)

func Extension(name string) string {
	return strings.ToLower(filepath.Ext(name))
}

func CategoryFor(name string) Category {
	ext := Extension(name)
	switch {
	case oneOf(ext, ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tif", ".tiff"):
		return Visual
	case oneOf(ext, ".mp4", ".mov", ".m4v", ".avi", ".mkv", ".webm", ".mpeg", ".mpg", ".3gp", ".mts", ".m2ts", ".wmv", ".flv", ".ogv", ".vob", ".ts"):
		return Video
	case oneOf(ext, ".txt", ".md", ".markdown", ".csv", ".tsv", ".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".log", ".html", ".htm", ".css", ".js", ".ts", ".sql", ".sh", ".py", ".go", ".rs", ".java", ".c", ".h", ".cpp", ".hpp", ".rb", ".php", ".swift", ".conf", ".properties", ".rst", ".tex", ".ps1", ".bat"):
		return Text
	case oneOf(ext, ".pdf", ".rtf", ".doc", ".docx", ".docm", ".odt", ".pages", ".ppt", ".pptx", ".xls", ".xlsx", ".epub"):
		return Document
	default:
		return Other
	}
}

func oneOf(value string, choices ...string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}
