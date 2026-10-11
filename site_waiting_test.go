package main

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// A site whose config/ is a bind of the data root (D9) keeps site posture
// while the data root is not mounted, and restarts once its config is
// readable; an absent config anywhere else is still a machine with no site.

func siteWaitingFixture(t *testing.T, recorded, mounted bool) (configPath string) {
	t.Helper()
	dir := t.TempDir()
	site := filepath.Join(dir, "var/www/html/lukssite")
	if err := os.MkdirAll(filepath.Join(site, "config"), 0755); err != nil {
		t.Fatal(err)
	}
	binds := filepath.Join(dir, "data_binds")
	body := "# Written by joinery_data_root.sh\nsites/lukssite/uploads " + filepath.Join(site, "uploads") + "\n"
	if recorded {
		body += "sites/lukssite/config " + filepath.Join(site, "config") + "\n"
	}
	os.WriteFile(binds, []byte(body), 0644)
	mi := filepath.Join(dir, "mountinfo")
	mbody := "22 1 252:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw\n"
	if mounted {
		mbody += "90 22 252:2 /sites/lukssite/config " + filepath.Join(site, "config") + " rw,relatime shared:50 - xfs /dev/mapper/joinery-data rw\n"
	}
	os.WriteFile(mi, []byte(mbody), 0644)
	oldB, oldM := dataBindsPath, mountInfoPath
	dataBindsPath, mountInfoPath = binds, mi
	t.Cleanup(func() { dataBindsPath, mountInfoPath = oldB, oldM })
	configPath = filepath.Join(site, "config", "Globalvars_site.php")
	t.Setenv("JOINERY_CONFIG", configPath)
	return configPath
}

func TestSiteConfigOnALockedDataRootKeepsSitePosture(t *testing.T) {
	siteWaitingFixture(t, true, false)
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Siteless || !cfg.SiteWaiting || !filepath.IsAbs(cfg.SiteRoot) || filepath.Base(cfg.SiteRoot) != "lukssite" || cfg.DBPassword != "" {
		t.Fatalf("a locked site's machine is not a waiting site: siteless=%v waiting=%v root=%q", cfg.Siteless, cfg.SiteWaiting, cfg.SiteRoot)
	}
}

func TestAbsentConfigElsewhereIsStillSiteless(t *testing.T) {
	for _, c := range []struct {
		name              string
		recorded, mounted bool
	}{
		{"config not on the data root", false, false},
		{"its bind mounted, and still no config", true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			siteWaitingFixture(t, c.recorded, c.mounted)
			cfg, err := LoadConfig()
			if err != nil {
				t.Fatal(err)
			}
			if !cfg.Siteless || cfg.SiteWaiting || cfg.SiteRoot != "" {
				t.Fatalf("siteless=%v waiting=%v root=%q", cfg.Siteless, cfg.SiteWaiting, cfg.SiteRoot)
			}
		})
	}
}

func TestWaitingSiteRestartsOnceItsConfigIsReadable(t *testing.T) {
	path := siteWaitingFixture(t, true, false)
	oldI, oldE := siteConfigWatchInterval, siteConfigWatchExit
	t.Cleanup(func() { siteConfigWatchInterval, siteConfigWatchExit = oldI, oldE })
	siteConfigWatchInterval = 10 * time.Millisecond
	exited := make(chan struct{})
	siteConfigWatchExit = func() { close(exited) }
	var jobLock sync.Mutex
	go watchSiteConfig(path, &jobLock)

	select {
	case <-exited:
		t.Fatal("restarted before the config was there")
	case <-time.After(60 * time.Millisecond):
	}
	// A job running holds it back until the job is done.
	jobLock.Lock()
	os.WriteFile(path, []byte("<?php\n$this->settings['dbname'] = 'lukssite';\n$this->settings['dbpassword'] = 'x';\n"), 0640)
	select {
	case <-exited:
		t.Fatal("restarted under a running job")
	case <-time.After(60 * time.Millisecond):
	}
	jobLock.Unlock()
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		t.Fatal("did not restart once its config was readable")
	}
}
