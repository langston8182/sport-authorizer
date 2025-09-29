// npm i js-yaml
import yaml from "js-yaml";
import {
    AppConfigDataClient,
    StartConfigurationSessionCommand,
    GetLatestConfigurationCommand,
} from "@aws-sdk/client-appconfigdata";

const client = new AppConfigDataClient({});
// Cache par profil (évite de rappeler AppConfig à chaque invocation)
const sessionTokens = new Map();  // profile -> token
const profileCache = new Map();  // profile -> parsed config (object or string)

/**
 * Charge un profil AppConfig et retourne:
 *  - un objet JS si le contenu est JSON ou YAML
 *  - une string si le contenu est une simple chaîne (ex: secret brut)
 */
export async function loadProfile(profileName, {
    app = process.env.APP_NAME,
    env = process.env.ENVIRONMENT,
} = {}) {
    // Retourne du cache si déjà chargé dans ce runtime
    if (profileCache.has(profileName)) return profileCache.get(profileName);

    // Démarre la session si besoin
    let token = sessionTokens.get(profileName);
    if (!token) {
        const start = await client.send(new StartConfigurationSessionCommand({
            ApplicationIdentifier: app,
            EnvironmentIdentifier: env,
            ConfigurationProfileIdentifier: profileName,
        }));
        token = start.InitialConfigurationToken;
        sessionTokens.set(profileName, token);
    }

    // Récupère la config
    const resp = await client.send(new GetLatestConfigurationCommand({
        ConfigurationToken: token,
    }));
    if (!resp.Configuration) {
        throw new Error(`AppConfig profile '${profileName}' returned empty payload`);
    }

    const raw = new TextDecoder().decode(resp.Configuration);

    // Essaie JSON → YAML → string
    let parsed;
    try {
        parsed = JSON.parse(raw);
    } catch {
        try {
            parsed = yaml.load(raw);
        } catch {
            parsed = raw;
        }
    }

    profileCache.set(profileName, parsed);
    return parsed;
}

/**
 * Récupère une valeur précise dans un profil AppConfig.
 * @param {string} profileName Nom du profil AppConfig
 * @param {string} key Chemin de la clé (dot notation: ex "db.MONGODB_URI")
 * @param {*} fallback Valeur par défaut si la clé n'existe pas
 * @param opts
 */
export async function getConfigValue(profileName, key, fallback = undefined, opts = {}) {
    const cfg = await loadProfile(profileName, opts);

    if (!key) return cfg;

    // navigation "dot path"
    return key.split(".").reduce((acc, part) => {
        if (acc && typeof acc === "object" && part in acc) {
            return acc[part];
        }
        return fallback;
    }, cfg);
}
