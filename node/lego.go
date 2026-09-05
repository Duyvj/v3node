package node

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"encoding/json"

	commonfile "github.com/Duyvj/v3node/common/file"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"

	panel "github.com/Duyvj/v3node/api/v2board"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
)

type Lego struct {
	client *lego.Client
	config *panel.CertInfo
}

const maxACMEAccountBytes int64 = 1 << 20

var certificateOperationLocks sync.Map // map[string]*sync.Mutex

func certificateOperationLock(certFile, keyFile string) *sync.Mutex {
	key := filepath.Clean(certFile) + "\x00" + filepath.Clean(keyFile)
	value, _ := certificateOperationLocks.LoadOrStore(key, &sync.Mutex{})
	return value.(*sync.Mutex)
}

func NewLego(config *panel.CertInfo) (*Lego, error) {
	resolved, err := resolvedLegoConfig(config)
	if err != nil {
		return nil, err
	}
	accountPath := filepath.Join(filepath.Dir(resolved.CertFile),
		"user",
		fmt.Sprintf("user-%s.json", resolved.Email))
	if err := validateCertificatePath(accountPath, true); err != nil {
		return nil, fmt.Errorf("validate ACME account path: %w", err)
	}
	user, err := NewLegoUser(accountPath, resolved.Email)
	if err != nil {
		return nil, fmt.Errorf("create user error: %s", err)
	}
	c := lego.NewConfig(user)
	c.Certificate.KeyType = certcrypto.RSA2048
	client, err := lego.NewClient(c)
	if err != nil {
		return nil, err
	}
	l := Lego{
		client: client,
		config: resolved,
	}
	err = l.SetProvider()
	if err != nil {
		return nil, fmt.Errorf("set provider error: %s", err)
	}
	return &l, nil
}

func (l *Lego) SetProvider() error {
	switch l.config.CertMode {
	case "http":
		err := l.client.Challenge.SetHTTP01Provider(http01.NewProviderServer("", "80"))
		if err != nil {
			return err
		}
	case "dns", "auto":
		p, err := newDNSChallengeProvider(l.config.Provider, l.config.DNSEnv)
		if err != nil {
			return fmt.Errorf("create dns challenge provider error: %s", err)
		}
		err = l.client.Challenge.SetDNS01Provider(p)
		if err != nil {
			return fmt.Errorf("set dns provider error: %s", err)
		}
	}
	return nil
}

func newDNSChallengeProvider(provider string, environment map[string]string) (challenge.Provider, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider != "cloudflare" {
		return nil, fmt.Errorf("unsupported DNS provider %q", provider)
	}
	allowed := map[string]struct{}{
		"CF_DNS_API_TOKEN":         {},
		"CLOUDFLARE_DNS_API_TOKEN": {},
	}
	for key := range environment {
		if _, ok := allowed[key]; !ok {
			return nil, fmt.Errorf("unsupported DNS credential variable %q", key)
		}
	}

	// Import the Cloudflare provider directly. The generic Lego provider
	// registry links every supported DNS SDK into the privileged Agent even
	// though ZBoard deliberately accepts Cloudflare only. Keeping the concrete
	// provider removes a large, unused dependency and attack surface. Build its
	// config directly as well: putting a write-only DNS token in os.Environ, even
	// briefly, lets a concurrent privileged subprocess inherit the credential.
	token := strings.TrimSpace(environment["CLOUDFLARE_DNS_API_TOKEN"])
	legacyToken := strings.TrimSpace(environment["CF_DNS_API_TOKEN"])
	if token != "" && legacyToken != "" && token != legacyToken {
		return nil, fmt.Errorf("conflicting Cloudflare DNS API tokens")
	}
	if token == "" {
		token = legacyToken
	}
	if token == "" || len(token) > 512 || strings.IndexFunc(token, func(r rune) bool {
		return r < 0x20 || r == 0x7f
	}) >= 0 {
		return nil, fmt.Errorf("invalid Cloudflare DNS API token")
	}
	cloudflareConfig := cloudflare.NewDefaultConfig()
	cloudflareConfig.AuthToken = token
	cloudflareConfig.ZoneToken = token
	return cloudflare.NewDNSProviderConfig(cloudflareConfig)
}

func resolvedCertificateConfig(config *panel.CertInfo) (*panel.CertInfo, error) {
	if config == nil {
		return nil, fmt.Errorf("certificate settings are missing")
	}
	resolved := *config
	replacer := strings.NewReplacer(
		"{domain}", resolved.CertDomain,
		"{email}", resolved.Email,
	)
	resolved.CertFile = replacer.Replace(resolved.CertFile)
	resolved.KeyFile = replacer.Replace(resolved.KeyFile)
	return &resolved, nil
}

func resolvedLegoConfig(config *panel.CertInfo) (*panel.CertInfo, error) {
	resolved, err := resolvedCertificateConfig(config)
	if err != nil {
		return nil, err
	}
	if len(resolved.Email) == 0 || len(resolved.Email) > 254 || strings.IndexFunc(resolved.Email, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("@._+-", r))
	}) >= 0 {
		return nil, fmt.Errorf("invalid ACME account email")
	}
	if err := validateCertificateMaterialPath(resolved.CertFile, false, true); err != nil {
		return nil, err
	}
	if err := validateCertificateMaterialPath(resolved.KeyFile, true, true); err != nil {
		return nil, err
	}
	if filepath.Clean(resolved.CertFile) == filepath.Clean(resolved.KeyFile) {
		return nil, fmt.Errorf("certificate and private-key paths must be different")
	}
	return resolved, nil
}

func (l *Lego) CreateCert() (err error) {
	return l.CreateCertContext(context.Background())
}

func (l *Lego) CreateCertContext(ctx context.Context) (err error) {
	lock := certificateOperationLock(l.config.CertFile, l.config.KeyFile)
	lock.Lock()
	defer lock.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	request := certificate.ObtainRequest{
		Domains: []string{l.config.CertDomain},
		Bundle:  true,
	}
	certificates, err := l.client.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("obtain certificate error: %s", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	err = l.writeCert(certificates)
	if err != nil {
		return fmt.Errorf("write certificate error: %s", err)
	}
	return nil
}

func (l *Lego) RenewCert() error {
	return l.RenewCertContext(context.Background())
}

func (l *Lego) RenewCertContext(ctx context.Context) error {
	lock := certificateOperationLock(l.config.CertFile, l.config.KeyFile)
	lock.Lock()
	defer lock.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	file, err := commonfile.ReadRegularFileLimited(l.config.CertFile, maxCertificateMaterialBytes)
	if err != nil {
		return fmt.Errorf("read cert file error: %s", err)
	}
	if e, err := l.CheckCert(file); !e {
		return nil
	} else if err != nil {
		return fmt.Errorf("check cert error: %s", err)
	}
	res, err := l.client.Certificate.Renew(certificate.Resource{
		Domain:      l.config.CertDomain,
		Certificate: file,
	}, true, false, "")
	if err != nil {
		return err
	}
	// Lego itself does not accept a context. If shutdown/reload happened while
	// the ACME call was in flight, discard the result instead of letting an old
	// controller overwrite certificate files used by the replacement runtime.
	if err := ctx.Err(); err != nil {
		return err
	}
	err = l.writeCert(res)
	if err != nil {
		return fmt.Errorf("write certificate error: %s", err)
	}
	return nil
}

func (l *Lego) CheckCert(file []byte) (bool, error) {
	cert, err := certcrypto.ParsePEMCertificate(file)
	if err != nil {
		return false, err
	}
	notAfter := int(time.Until(cert.NotAfter).Hours() / 24.0)
	if notAfter > 30 {
		return false, nil
	}
	return true, nil
}
func (l *Lego) parseParams(path string) string {
	r := strings.NewReplacer("{domain}", l.config.CertDomain,
		"{email}", l.config.Email)
	return r.Replace(path)
}
func (l *Lego) writeCert(certificates *certificate.Resource) error {
	certPath := l.parseParams(l.config.CertFile)
	if err := writeCertificateFile(certPath, certificates.Certificate, 0o644); err != nil {
		return err
	}
	keyPath := l.parseParams(l.config.KeyFile)
	if err := writeCertificateFile(keyPath, certificates.PrivateKey, 0o600); err != nil {
		_ = os.Remove(certPath)
		return err
	}
	return nil
}

type User struct {
	Email        string                 `json:"Email"`
	Registration *registration.Resource `json:"Registration"`
	key          crypto.PrivateKey
	KeyEncoded   string `json:"Key"`
}

func (u *User) GetEmail() string {
	return u.Email
}
func (u *User) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func NewLegoUser(path string, email string) (*User, error) {
	var user User
	info, statErr := os.Lstat(path)
	if statErr == nil {
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("ACME account path is not a regular file")
		}
		if info.Size() < 1 || info.Size() > maxACMEAccountBytes {
			return nil, fmt.Errorf("ACME account file must be between 1 byte and %d bytes", maxACMEAccountBytes)
		}
		err := user.Load(path)
		if err != nil {
			return nil, err
		}
		if user.Email != email {
			user.Registration = nil
			user.Email = email
			err := registerUser(&user, path)
			if err != nil {
				return nil, err
			}
		}
	} else if os.IsNotExist(statErr) {
		user.Email = email
		err := registerUser(&user, path)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("inspect ACME account: %w", statErr)
	}
	return &user, nil
}

func registerUser(user *User, path string) error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key error: %s", err)
	}
	user.key = privateKey
	c := lego.NewConfig(user)
	client, err := lego.NewClient(c)
	if err != nil {
		return fmt.Errorf("create lego client error: %s", err)
	}
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return err
	}
	user.Registration = reg
	err = user.Save(path)
	if err != nil {
		return fmt.Errorf("save user error: %s", err)
	}
	return nil
}

func EncodePrivate(privKey *ecdsa.PrivateKey) (string, error) {
	encoded, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return "", err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded})
	return string(pemEncoded), nil
}
func (u *User) Save(path string) error {
	privateKey, ok := u.key.(*ecdsa.PrivateKey)
	if !ok || privateKey == nil {
		return fmt.Errorf("invalid ACME account private key")
	}
	encoded, err := EncodePrivate(privateKey)
	if err != nil {
		return fmt.Errorf("encode ACME account private key: %w", err)
	}
	u.KeyEncoded = encoded
	defer func() { u.KeyEncoded = "" }()
	data, err := json.Marshal(u)
	if err != nil {
		return fmt.Errorf("marshal json error: %s", err)
	}
	if err := writeCertificateFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write ACME account: %w", err)
	}
	return nil
}

func (u *User) DecodePrivate(pemEncodedPriv string) (*ecdsa.PrivateKey, error) {
	blockPriv, _ := pem.Decode([]byte(pemEncodedPriv))
	if blockPriv == nil || blockPriv.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("invalid ACME account private key PEM")
	}
	x509EncodedPriv := blockPriv.Bytes
	privateKey, err := x509.ParseECPrivateKey(x509EncodedPriv)
	return privateKey, err
}

func (u *User) Load(path string) error {
	data, err := commonfile.ReadRegularFileLimited(path, maxACMEAccountBytes)
	if err != nil {
		return fmt.Errorf("open file error: %s", err)
	}

	err = json.Unmarshal(data, u)
	if err != nil {
		return fmt.Errorf("unmarshal json error: %s", err)
	}
	u.key, err = u.DecodePrivate(u.KeyEncoded)
	if err != nil {
		return fmt.Errorf("decode private key error: %s", err)
	}
	u.KeyEncoded = ""
	return nil
}
