//go:build darwin

package apple

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
)

func Mount(encryptedArchive io.Reader, key string, cb func(mountPoint string) error) error {
	aeaPath, err := exec.LookPath("aea")
	if err != nil {
		return fmt.Errorf("unable to find required 'aea' command-line tool: %s", err.Error())
	}
	aaPath, err := exec.LookPath("aa")
	if err != nil {
		return fmt.Errorf("unable to find required 'aa' command-line tool: %s", err.Error())
	}
	hdiutilPath, err := exec.LookPath("hdiutil")
	if err != nil {
		return fmt.Errorf("unable to find required 'hdiutil' command-line tool: %s", err.Error())
	}

	workdir, err := os.MkdirTemp("", "")
	if err != nil {
		return fmt.Errorf("error creating temporary directory: %s", err.Error())
	}
	defer os.RemoveAll(workdir)

	encryptedArchivePath := path.Join(workdir, "encrypted.aar")
	f, err := os.OpenFile(encryptedArchivePath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("error writing file: %s", err.Error())
	}
	if _, err := io.Copy(f, encryptedArchive); err != nil {
		return fmt.Errorf("error writing file: %s", err.Error())
	}
	f.Close()
	decryptedArchivePath := path.Join(workdir, "decrypted.aar")

	output, err := exec.Command(aeaPath, "decrypt", "-i", encryptedArchivePath, "-o", decryptedArchivePath, "-key-value", "base64:"+key).CombinedOutput()
	if err != nil {
		if len(output) == 0 {
			return fmt.Errorf("error executing aea tool: %s", err.Error())
		}
		return fmt.Errorf("error executing aea tool: %s", output)
	}

	dummyDir, err := os.MkdirTemp(workdir, "dummy")
	if err != nil {
		return fmt.Errorf("error creating output directory: %s", err.Error())
	}
	archiveExtractDir, err := os.MkdirTemp(workdir, "extract")
	if err != nil {
		return fmt.Errorf("error creating output directory: %s", err.Error())
	}

	output, err = exec.Command(aaPath, "patch", "-i", decryptedArchivePath, "-src", dummyDir, "-dst", archiveExtractDir).CombinedOutput()
	os.RemoveAll(dummyDir)
	if err != nil {
		if len(output) == 0 {
			return fmt.Errorf("error executing aa tool: %s", err.Error())
		}
		return fmt.Errorf("error executing aa tool: %s", output)
	}

	dmgPath := path.Join(archiveExtractDir, "AssetData", "Restore", "SECUREPKITRUSTSTOREASSETS_SECUREPKITRUSTSTORE_Cryptex.dmg")

	if _, err := os.Stat(dmgPath); err != nil {
		return fmt.Errorf("unable to find .dmg after extracting archive")
	}

	mountDir, err := os.MkdirTemp(workdir, "mount")
	if err != nil {
		return fmt.Errorf("error creating mount directory: %s", err.Error())
	}

	output, err = exec.Command(hdiutilPath, "attach", dmgPath, "-readonly", "-nobrowse", "-noautoopen", "-mountpoint", mountDir).CombinedOutput()
	if err != nil {
		if len(output) == 0 {
			return fmt.Errorf("error executing hdiutil tool: %s", err.Error())
		}
		return fmt.Errorf("error executing hdiutil tool: %s", output)
	}

	err = cb(mountDir)

	exec.Command(hdiutilPath, "detach", mountDir).CombinedOutput()

	return err
}

func ConvertPlist(plistPath, jsonPath string) error {
	plutilPath, err := exec.LookPath("plutil")
	if err != nil {
		return fmt.Errorf("unable to find required 'plutil' command-line tool: %s", err.Error())
	}

	dst, err := os.OpenFile(jsonPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("Error coverting plist file: %s", err.Error())
	}
	defer dst.Close()
	src, err := os.Open(plistPath)
	if err != nil {
		return fmt.Errorf("Error coverting plist file: %s", err.Error())
	}
	defer src.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("Error coverting plist file: %s", err.Error())
	}
	dst.Sync()
	dst.Close()

	output, err := exec.Command(plutilPath, "-convert", "json", jsonPath).CombinedOutput()
	if err != nil {
		if len(output) == 0 {
			return fmt.Errorf("error executing plutil tool: %s", err.Error())
		}
		return fmt.Errorf("error executing plutil tool: %s", output)
	}

	return nil
}
