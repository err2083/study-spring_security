package light.star.study.service;

import java.util.List;

public interface SecurityService {

    public List<String> getList();

    public void saveSecurity();

    public void deleteSecurity();

    public String get(Long id);

    public List<String> getAllList();
}
