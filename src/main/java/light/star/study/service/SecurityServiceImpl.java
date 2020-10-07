package light.star.study.service;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SecurityServiceImpl implements SecurityService {

    @Override
    @Secured({"ROLE_USER", "ROLE_GUEST"})
    public List<String> getList() {
        return null;
    }

    @Override
    @Secured("ROLE_ADMIN")
    public void saveSecurity() {

    }

    @Override
    @PreAuthorize("hasAuthority('USER')")
    public void deleteSecurity() {

    }

    @Override
    @PostAuthorize("returnObject.owner == authentication.name")
    public String get(Long id) {
        return null;
    }

    @Override
    @PostFilter("hasAuthority('Admin') or filterObject.owner == authentication.name")
    public List<String> getAllList() {
        return null;
    }
}
