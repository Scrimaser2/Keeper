package ui

import "photovault/internal/vault"

type LibraryStorage interface {
	OpenSession(path, key string) (*vault.Session, error)
	Delete(path, key, name string) error
	AddTag(path, key, tag string, names []string) (int, error)
	ListTags(path, key string) ([]vault.Tag, error)
	CreateTag(path, key, name string) (vault.Tag, error)
	UpdateTag(path, key string, tag vault.Tag) error
	SaveTag(path, key string, tag vault.Tag) (vault.Tag, error)
	DeleteTag(path, key, tagID string) error
	AssignTag(path, key, tagID string, names []string) (int, error)
	RemoveTagFromItems(path, key, tagID string, names []string) (int, error)
}

type CreateStorage interface {
	Create(options vault.CreateOptions) (vault.CreateResult, error)
}

type RestoreStorage interface {
	Restore(options vault.RestoreOptions) error
}

type Storage interface {
	LibraryStorage
	CreateStorage
	RestoreStorage
}
