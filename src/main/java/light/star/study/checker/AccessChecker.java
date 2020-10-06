package light.star.study.checker;

import org.springframework.security.core.Authentication;

public class AccessChecker {

    public boolean hasLocalAccess(Authentication authentication) {
        return false;
    }
}
