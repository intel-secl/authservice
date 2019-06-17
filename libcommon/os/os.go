package os

import (
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
)

func GetDirFileContents(dir, pattern string) ([][]byte, error) {
	dirContents := make([][]byte, 0, 2)
	//if we are passed in an empty pattern, set pattern to * to match all files
	if pattern == "" {
		pattern = "*"
	}

	err := filepath.Walk(dir, func(fPath string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		if matched, _ := path.Match(pattern, info.Name()); matched == true {
			if content, err := ioutil.ReadFile(fPath); err == nil {
				dirContents = append(dirContents, content)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(dirContents) == 0 {
		return nil, fmt.Errorf("did not find any files with matching pattern %s for directory %s", pattern, dir)
	}
	return dirContents, nil
}
