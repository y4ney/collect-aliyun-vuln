package utils

import (
	"encoding/json"
	"golang.org/x/xerrors"
	"os"
)

func Mkdir(dir string) error {
	_, err := os.Stat(dir)
	if err == nil {
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}

	if err = os.MkdirAll(dir, os.ModePerm); err != nil {
		return err
	}
	return nil
}

func WriteFile(filepath string, data any) error {
	d, err := json.MarshalIndent(data, "", "\t")
	if err != nil {
		return xerrors.Errorf("failed to marshal:%w", err)
	}
	if err = os.WriteFile(filepath, d, os.ModePerm); err != nil {
		return xerrors.Errorf("failed to write to %s:%w", filepath, err)
	}

	return nil
}
