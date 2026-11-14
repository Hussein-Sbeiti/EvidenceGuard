/* Intentionally vulnerable educational fixture; do not build or deploy.
 * Historical dependency context: log4j-core 2.14.1, CVE-2021-44228.
 * The scanner looks up this CVE mention; it does not verify a dependency,
 * runtime configuration, or exploitability. No exploit payload is included.
 */
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

class VulnerableLog4j {
    private static final Logger logger = LogManager.getLogger(VulnerableLog4j.class);

    void logUntrustedInput(String userInput) {
        logger.info(userInput);
    }

    String demoCredential() {
        String api_key = "demo-only-not-a-real-key";
        return api_key;
    }
}
