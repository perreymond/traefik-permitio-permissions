package traefik_permitio_permissions

import (
    "context"
    "encoding/json"
    "fmt"
    "github.com/dgrijalva/jwt-go"
    "net/http"
)

// Config est la structure qui définit la configuration du middleware.
type Config struct {
    CookieName string `json:"cookieName,omitempty"`
    HeaderName string `json:"headerName,omitempty"`
    Secret     string `json:"secret,omitempty"`
}

// CreateConfig permet de créer une configuration par défaut pour le middleware.
func CreateConfig() *Config {
    return &Config{
        CookieName: "jwt_token", // Nom du cookie par défaut
        HeaderName: "Authorization", // Nom de l'en-tête par défaut
        Secret:     "your-secret-key", // Clé secrète pour vérifier la signature JWT
    }
}

// PermitioMiddleware est la structure du middleware.
type PermitioMiddleware struct {
    next       http.Handler
    cookieName string
    headerName string
    secret     string
}

// New permet de créer une nouvelle instance du middleware avec la configuration donnée.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
    return &PermitioMiddleware{
        next:       next,
        cookieName: config.CookieName,
        headerName: config.HeaderName,
        secret:     config.Secret,
    }, nil
}

// ServeHTTP est la fonction principale du middleware qui traite chaque requête.
func (p *PermitioMiddleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
    var tokenStr string

    // Récupération du JWT à partir du cookie ou de l'en-tête
    cookie, err := req.Cookie(p.cookieName)
    if err == nil {
        tokenStr = cookie.Value
    } else {
        tokenStr = req.Header.Get(p.headerName)
        if tokenStr == "" {
            http.Error(rw, "JWT non trouvé", http.StatusUnauthorized)
            return
        }
        // Si le token est dans l'en-tête Authorization, il peut avoir le format "Bearer <token>"
        tokenStr = extractBearerToken(tokenStr)
    }

    // Parse et vérification du JWT
    token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("méthode de signature inattendue")
        }
        return []byte(p.secret), nil
    })

    if err != nil {
        http.Error(rw, "JWT invalide", http.StatusUnauthorized)
        return
    }

    // Vérification des claims du JWT
    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        email, ok := claims["email"].(string)
        if !ok || email != "gilles@iofinnet.com" {
            http.Error(rw, "Utilisateur non autorisé", http.StatusForbidden)
            return
        }
    } else {
        http.Error(rw, "JWT invalide", http.StatusUnauthorized)
        return
    }

    // Si tout est bon, continuer vers le prochain handler
    p.next.ServeHTTP(rw, req)
}

// extractBearerToken extrait le token de l'en-tête "Bearer"
func extractBearerToken(authHeader string) string {
    const prefix = "Bearer "
    if len(authHeader) > len(prefix) && authHeader[:len(prefix)] == prefix {
        return authHeader[len(prefix):]
    }
    return authHeader
}
