---
typora-copy-images-to: img
---

# 密码加密与微服务鉴权JWT 

## 第一章-BCrypt密码加密 

### 1.准备工作 

​	任何应用考虑到安全，绝不能明文的方式保存密码。密码应该通过哈希算法进行加密。有很多标准的算法比如SHA或者MD5，结合salt(盐)是一个不错的选择。 Spring Security提供了BCryptPasswordEncoder类,实现Spring的PasswordEncoder接口使用BCrypt强哈希方法来加密密码。
​	BCrypt强哈希方法 每次加密的结果都不一样。 

+ tensquare_user工程的pom引入依赖  

```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-security</artifactId>
</dependency>	
```

+ 添加配置类 （资源/工具类中提供） 

  我们在添加了spring security依赖后，默认情况下所有的路径都被spring security所控制了，我们目前只是需要用到BCrypt密码加密的部分，所以我们要添加一个配置类，配置为所有地址都可以匿名访问。 

```java
package com.tensquare.user;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 *  安全配置类
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter{
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //authorizeRequests: 请求授权
        //antMatchers("/**").permitAll(): 任何用户都可以访问任何资源
        //anyRequest().authenticated(): 没有匹配上面的路径,只有用户被认证
        //and().csrf().disable(): 关闭跨域安全请求
        http
				.authorizeRequests()
                .antMatchers("/**").permitAll()
                .anyRequest().authenticated()
                .and().csrf().disable();
    }
}
```

步骤: 

1. 在Spring容器里面注册BCryptPasswordEncoder
2. 在业务层注入BCryptPasswordEncoder
3. 在注册的业务里面,使用BCryptPasswordEncoder对密码进行加密







+ 修改tensquare_user工程的UserApplication, 配置bean 

```java
@Bean
public BCryptPasswordEncoder bcryptPasswordEncoder(){
    return new BCryptPasswordEncoder();
}
```

### 2.管理员密码加密 

#### 2.1新增管理员密码加密 

+ 修改tensquare_user工程的AdminService 的add方法

```java
	@Autowired
	private BCryptPasswordEncoder encoder;
	/**
	 * 增加
	 * @param admin
	 */
	public void add(Admin admin) {
		admin.setId( idWorker.nextId()+"" );
		//加密密码
		String newPassword = encoder.encode(admin.getPassword());
		admin.setPassword(newPassword);
		adminDao.save(admin);
	}
```

#### 2.2管理员登陆密码校验 

![1537352283004](img/1537352283004.png)

+ AdminController

```java
    /**
     * 登录
     * @return
     */
    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public Result login(@RequestBody Map<String, String> map) {
        Admin admin = adminService.findByLoginNameAndPassword(map.get("loginname"), map.get("password"));
		if(admin != null){
            return new Result(true, StatusCode.OK, "登录成功");
        }else{
            return new Result(true, StatusCode.LOGINERROR, "登录失败");
        }
    }
```

+ AdminService

```java
	public Admin findByLoginNameAndPassword(String loginname, String password) {
		Admin admin = adminDao.findByLoginname(loginname);
		if(admin != null && encoder.matches(password,admin.getPassword())){
			return  admin;
		}else{
			return  null;
		}
	}
```

+ AdminDao

```java
Admin findByLoginname(String loginname);
```

### 3.用户密码加密

#### 3.1用户注册密码加密 

+ 修改tensquare_user工程的UserService 的add方法

```java
	@Autowired
	private BCryptPasswordEncoder encoder;

	/**
	 * 增加
	 * @param user
	 * @param code
	 */
	public void add(User user, String code) {
		String smscode  = (String) redisTemplate.opsForValue().get("smscode_" + user.getMobile());
		if(smscode == null || "".equals(smscode)){
			throw  new RuntimeException("请点击获取短信验证码");
		}

		if(!smscode.equals(code)){
			throw  new RuntimeException("验证码输入不正确");
		}

		user.setId( idWorker.nextId()+"" );
		user.setFollowcount(0);//关注数
		user.setFanscount(0);//粉丝数
		user.setOnline(0L);//在线时长
		user.setRegdate(new Date());//注册日期
		user.setUpdatedate(new Date());//更新日期
		user.setLastdate(new Date());//最后登陆日期

		String newPassword = encoder.encode(user.getPassword());
		user.setPassword(newPassword);

		userDao.save(user);
	}
```

#### 3.2用户登陆密码判断 

![1537353189534](img/1537353189534.png)

+ UserController

```java
	/**
	 * 登录
	 * @return
	 */
	@RequestMapping(value = "/login", method = RequestMethod.POST)
	public Result login(@RequestBody Map<String, String> map) {
		User user = userService.findByMobileAndPassword(map.get("mobile"), map.get("password"));
		if(user != null){
			return new Result(true, StatusCode.OK, "登录成功");
		}else{java
			return new Result(true, StatusCode.LOGINERROR, "登录失败");
		}
	}
```

+ UserService

```java
	public User findByMobileAndPassword(String mobile, String password) {
    	User user =  userDao.findByMobile(mobile);
    	if(user != null && encoder.matches(password,user.getPassword())){
    		return  user;
		}else{
    		return  null;
		}
	}
```

+ UserDao

```java
User findByMobile(String mobile);
```

## 第二章-常见的认证机制  

### 1.HTTP Basic Auth 

​	HTTP Basic Auth简单点说明就是每次请求API时都提供用户的username和password，简言之，Basic Auth是配合RESTful API 使用的最简单的认证方式，只需提供用户名密码即可，但由于有把用户名密码暴露给第三方客户端的风险，在生产环境下被使用的越来越少。因此，在开发对外开放的RESTful API时，尽量避免采用HTTP BasicAuth 

### 2.Cookie Auth 

​	Cookie认证机制就是为一次请求认证在服务端创建一个Session对象，同时在客户端的浏览器端创建了一个Cookie对象；通过客户端带上来Cookie对象来与服务器端的session对象匹配来实现状态管理的。默认的，当我们关闭浏览器的时候，cookie会被删除。但可以通过修改cookie 的expire time使cookie在一定时间内有效 

![img](img/1537330393720.png)

### 3.OAuth 

#### 3.1OAuth2.0是什么  

​	OAuth简单说就是一种授权的**协议**，允许用户让第三方应用访问该用户在某一web服务上存储的私密的资源（如照片，视频，联系人列表），而无需将用户名和密码提供给第三方应用。

​	举个例子，你想登录豆瓣去看看电影评论，但你丫的从来没注册过豆瓣账号，又不想新注册一个再使用豆瓣，怎么办呢？不用担心，豆瓣已经为你这种懒人做了准备，用你的qq号可以授权给豆瓣进行登录，请看。

+ 第一步：在豆瓣官网点击用qq登录

![1539435513038](img/1539435513038.png)

+ 第二步: 跳转到qq登录页面输入用户名密码，然后点授权并登录

![1539435554353](img/1539435554353.png)

+ 第三步: 跳回到豆瓣页面，成功登录

![1539435607854](img/1539435607854.png)



上面例子的流程:

![1539436138591](img/1539436138591.png)

#### 3.2OAuth2.0认证流程



​	OAuth允许用户提供一个令牌，而不是用户名和密码来访问他们存放在特定服务提供者的数据。每一个令牌授权一个特定的第三方系统（例如，视频编辑网站)在特定的时段（例如，接下来的2小时内）内访问特定的资源（例如仅仅是某一相册中的视频）。这样，OAuth让用户可以授权第三方网站访问他们存储在另外服务提供者的某些特定信息，而非所有内容.

​	下面是OAuth2.0的流程 

![1537330522775](img/1537330522775.png)

### 4.Token Auth  

使用基于 Token 的身份验证方法，在服务端不需要存储用户的登录记录。大概的流程是这样的：

1. 客户端使用用户名跟密码请求登录

2. 服务端收到请求，去验证用户名与密码

3. 验证成功后，服务端会签发一个 Token，再把这个 Token 发送给客户端

4. 客户端收到 Token 以后可以把它存储起来，比如放在 Cookie 里

5. 客户端每次向服务端请求资源的时候需要带着服务端签发的 Token

6. 服务端收到请求，然后去验证客户端请求里面带着的 Token，如果验证成功，就向
   客户端返回请求的数据 

   

![1537330818766](img/1537330818766.png)

Token机制相对于Cookie(Session)机制又有什么好处呢？  

+ 支持跨域访问: Cookie是不允许垮域访问的，这一点对Token机制是不存在的，前提是传输的用户认证信息通过HTTP头传输.
+ 无状态(也称：服务端可扩展行):Token机制在服务端不需要存储session信息，因为Token 自身包含了所有登录用户的信息，只需要在客户端的cookie或本地介质存储状态信息.
+ 更适用CDN: 可以通过内容分发网络请求你服务端的所有资料（如：javascript，HTML,图片等），而你的服务端只要提供API即可.
+ 去耦: 不需要绑定到一个特定的身份验证方案。Token可以在任何地方生成，只要在你的API被调用的时候，你可以进行Token生成调用即可.
+ ==更适用于移动应用==: 当你的客户端是一个原生平台（iOS, Android，Windows 8等）时，Cookie是不被支持的（你需要通过Cookie容器进行处理），这时采用Token认证机制就会简单得多。 



+ CSRF: 因为不再依赖于Cookie，所以你就不需要考虑对CSRF（跨站请求伪造）的防范。
+ 性能: 一次网络往返时间（通过数据库查询session信息）总比做一次HMACSHA256计算 的Token验证和解析要费时得多.
+ 不需要为登录页面做特殊处理: 如果你使用Protractor 做功能测试的时候，不再需要为登录页面做特殊处理. 
+ 基于标准化: 你的API可以采用标准化的 JSON Web Token (JWT). 这个标准已经存在多个后端库（.NET, Ruby, Java,Python, PHP）和多家公司的支持（如：Firebase,Google, Microsoft）. 

## 第三章-基于JWT的Token认证  

### 1.什么是JWT 

​	JSON Web Token（JWT）是一个非常轻巧的规范。

​	JWT工作原理服务器认证(第一次登录成功)以后，生成一个 JSON 对象(token串)，发回给用户，以后，用户与服务端通信的时候，都要发回这个 JSON 对象。服务器完全只靠这个对象认定用户身份。为了防止用户篡改数据，服务器在生成这个对象的时候，会加上签名.

​	服务器就不保存任何 session 数据了，也就是说，服务器变成无状态了，从而比较容易实现扩展

### 2.JWT组成 

+ 一个JWT实际上就是一个字符串，它由三部分组成，==头部、载荷与签证==。 中间通过.隔开

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ
```

+ 写成一行，就是下面的样子

```
Header.Payload.Signature
```

#### 2.1头部（Header） 

+ Header 部分是一个 JSON 对象，描述 JWT 的元数据,通常是下面的样子。 

```
{"typ":"JWT","alg":"HS256"} --通过base64编码-->eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9
```

上面代码中，

​	`typ`属性表示这个令牌（token）的类型（type），JWT 令牌统一写为`JWT`;

​	`alg`属性表示签名的算法（algorithm），默认是 HMAC SHA256（写成 HS256）

+ JWT生成的时候会对Header进行Base64编码.我们可以模拟一下https://www.sojson.com/base64.html，编码后的字符串如下： 

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9
```

#### 2.2载荷（playload） 

Payload 载荷就是存放有效信息的地方。Payload 部分也是一个 JSON 对象，用来==存放实际需要传递的数据==。

+ JWT 规定了7个官方字段，供选用。  

```
iss (issuer)：签发人
exp (expiration time)：过期时间
sub (subject)：主题
aud (audience)：受众
nbf (Not Before)：生效时间
iat (Issued At)：签发时间
jti (JWT ID)：编号
```

+ 除了官方字段，你还可以在这个部分自定义私有字段(这个指的就是自定义的claim。比如下面例子中的admin和name都属于自定的claim )。注意，JWT 默认是不加密的，任何人都可以读到，所以不要把秘密信息放在这个部分。

  eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9

```
{"sub":"张三","name":"John Doe","role":"admin"}
```

+ 这个 JSON 对象也要使用 Base64URL 算法转成字符串,得到Jwt的第二部分。 

```
eyJzdWIiOiLlvKDkuIkiLCJuYW1lIjoiSm9obiBEb2UiLCJyb2xlIjoiYWRtaW4ifQ==
```

#### 2.3签证（signature） 

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ
```

​	Signature 部分是对前两部分的签名，防止数据篡改。

​	首先，需要指定一个密钥（secret）。这个密钥只有服务器才知道，不能泄露给用户。一旦客户端得知这个secret, 那就意味着客户端是可以自我签发jwt了。 然后，使用 Header 里面指定的签名算法（默认是 HMAC SHA256），按照下面的公式产生签名

(编码之后头+编码之后的载荷+ secret(秘钥))用HMACSHA256加密算法算出来的一个字符串

```
HMACSHA256(base64UrlEncode(header) + "." +base64UrlEncode(payload),secret)
```

下面是对上面前两部分一个签名的例子

```
TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ
```

### 3.JWT的认证过程

![img](img/tu_1.png)

## 第四章-Java的JJWT实现JWT 

### 1.什么是JJWT  	 

​	 JJWT是一个提供服务器端到客户端端的JWT创建和验证的Java库。永远免费和开源(ApacheLicense，版本2.0)，JJWT很容易使用和理解。它被设计成一个以建筑为中心的流畅界面，隐藏了它的大部分复杂性。 

### 2.JJWT快速入门 

![1537342775427](img/1537342775427.png)

#### 2.1token的创建 

+ 创建maven工程，引入依赖 

```xml
    <dependencies>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt</artifactId>
            <version>0.6.0</version>
        </dependency>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.12</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
```

+ 创建类CreateJwtTest，用于生成token 

```java
public class CreateJwtTest {

    @Test
    public void fun01(){
        JwtBuilder builder= Jwts.builder().setId("888")
                .setSubject("小白")
                .setIssuedAt(new Date())
                .signWith(SignatureAlgorithm.HS256,"itcast");
        System.out.println( builder.compact() );
    }

}
```

​	setIssuedAt用于设置签发时间

​	signWith用于设置签名秘钥 

+ 测试运行，输出如下 

```
eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI4ODgiLCJzdWIiOiLlsI_nmb0iLCJpYXQiOjE1MzczNDI5NTR9.E4VaYTiq9MCXqjT0hBXl5Rxlo9kmGx4568DH6iEndHs
```

再次运行，会发现每次运行的结果是不一样的，因为我们的载荷中包含了时间。 

#### 2.2token的解析 

​	我们刚才已经创建了token ，在web应用中这个操作是由服务端进行然后发给客户端，客户端在下次向服务端发送请求时需要携带这个token（这就好像是拿着一张门票一样），那服务端接到这个token 应该解析出token中的信息（例如用户id）,根据这些信息查询数据库返回相应的结果 .

+ 创建ParseJwtTest 


```java
/**
 * 解析token
 */
public class ParseJwtTest {

    @Test
    public void fun01(){
        String token="eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI4ODgiLCJzdWIiOiLlsI_nmb0iLCJpYXQiOjE1MzczNDI5NTR9.E4VaYTiq9MCXqjT0hBXl5Rxlo9kmGx4568DH6iEndHs";
        Claims claims = Jwts.parser().setSigningKey("itcast").parseClaimsJws(token).getBody();
        System.out.println("id:"+claims.getId());
        System.out.println("subject:"+claims.getSubject());
        System.out.println("IssuedAt:"+claims.getIssuedAt());
    }

}
```


#### 2.3token过期校验 

​	有很多时候，我们并不希望签发的token是永久生效的，所以我们可以为token添加一个过期时间 

+ 在CreateJwtTest增加一个测试方法

```java
    @Test
    //为token添加一个过期时间
    public void fun02(){
        //为了方便测试，我们将过期时间设置为1分钟
        long now = System.currentTimeMillis();//当前时间
        long exp = now + 1000*60;//过期时间为1分钟

        JwtBuilder builder= Jwts.builder().setId("999")
                .setSubject("小黑")
                .setIssuedAt(new Date()).setExpiration(new Date(exp))
                .signWith(SignatureAlgorithm.HS256,"itcast");
        System.out.println( builder.compact() );

    }
```

+ 在ParseJwtTest增加一个测试方法

```
    @Test
    public void fun02(){
        String compactJws="eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI5OTkiLCJzdWIiOiLlsI_pu5EiLCJpYXQiOjE1MzczNDMyOTQsImV4cCI6MTUzNzM0MzM1NH0.n-W1lsvlNwggkhwi0-XpgXGbFXgxXhbHz4f8kOg-Q7U";
        Claims claims = Jwts.parser().setSigningKey("itcast").parseClaimsJws(compactJws).getBody();
        System.out.println("id:"+claims.getId());
        System.out.println("subject:"+claims.getSubject());
        SimpleDateFormat sdf=new SimpleDateFormat("yyyy‐MM‐dd hh:mm:ss");
        System.out.println("签发时间:"+sdf.format(claims.getIssuedAt()));
        System.out.println("过期时间:"+sdf.format(claims.getExpiration()));
        System.out.println("当前时间:"+sdf.format(new Date()) );
    }
```

如果过期了,会出现如下bug:

![1537343414019](img/1537343414019.png)

#### 2.4自定义claims 

​	我们刚才的例子只是存储了id和subject两个信息，如果你想存储更多的信息（例如角色）可以自定义claims 

+ 在CreateJwtTest增加一个测试方法

```java
    @Test
    //为token添加一个过期时间,自定义claims
    public void fun03(){
        //为了方便测试，我们将过期时间设置为1分钟
        long now = System.currentTimeMillis();//当前时间
        long exp = now + 1000*60;//过期时间为1分钟

        JwtBuilder builder= Jwts.builder().setId("999")
                .setSubject("小黑")
                .setIssuedAt(new Date())
                .setExpiration(new Date(exp))
                .claim("roles","admin")
                .claim("logo","logo.png")
                .signWith(SignatureAlgorithm.HS256,"itcast");
        System.out.println( builder.compact() );

    }
```

+ 在ParseJwtTest增加一个测试方法

```java
    @Test
    public void fun03(){
        String compactJws="eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI5OTkiLCJzdWIiOiLlsI_pu5EiLCJpYXQiOjE1MzczNDM1NTUsImV4cCI6MTUzNzM0Mzg1NSwicm9sZXMiOiJhZG1pbiIsImxvZ28iOiJsb2dvLnBuZyJ9.g2L1kDAdNnvlbPqSm9OdGxVcBU0h3SBGa8PzNfoTOog";
        Claims claims = Jwts.parser().setSigningKey("itcast").parseClaimsJws(compactJws).getBody();
        System.out.println("id:"+claims.getId());
        System.out.println("subject:"+claims.getSubject());
        SimpleDateFormat sdf=new SimpleDateFormat("yyyy‐MM‐dd hh:mm:ss");
        System.out.println("签发时间:"+sdf.format(claims.getIssuedAt()));
        System.out.println("过期时间:"+sdf.format(claims.getExpiration()));
        System.out.println("当前时间:"+sdf.format(new Date()) );
        System.out.println("角色:"+claims.get("roles") );
        System.out.println("logo:"+claims.get("logo") );
    }
```

## 第五章-十次方微服务鉴权 

### 1.JWT工具类的导入

+ tensquare_common工程引入依赖（考虑到工具类的通用性） 

```xml
    <dependencies>
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt</artifactId>
            <version>0.6.0</version>
        </dependency>
    </dependencies>
```

+ 把JwtUtil拷贝到tensquare_common下的util包

```java
package util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.Date;

/**
 * JWT工具类
 */
@ConfigurationProperties("jwt.config")
public class JwtUtil {

    private String key ;

    private long ttl ;

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public long getTtl() {
        return ttl;
    }

    public void setTtl(long ttl) {
        this.ttl = ttl;
    }

    /**
     * 生成JWT
     *
     * @param id
     * @param subject
     * @return
     */
    public String createJWT(String id, String subject, String roles) {
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        JwtBuilder builder = Jwts.builder().setId(id)
                .setSubject(subject)
                .setIssuedAt(now)
                .signWith(SignatureAlgorithm.HS256, key).claim("roles", roles);
        if (ttl > 0) {
            builder.setExpiration( new Date( nowMillis + ttl));
        }
        return builder.compact();
    }

    /**
     * 解析JWT
     * @param jwtStr
     * @return
     */
    public Claims parseJWT(String jwtStr){
        return  Jwts.parser()
                .setSigningKey(key)
                .parseClaimsJws(jwtStr)
                .getBody();
    }

}
```

+ 修改tensquare_user工程的application.yml, 添加配置 

```yml
jwt:
  config:
     key: itcast
     ttl: 360000
```

### 2.管理员登陆后台签发token 

#### 2.1需求分析

​	管理员登录成功后,签发token 响应给客户端.(返回token,登录名)

#### 2.2代码实现

+ 配置bean .修改tensquare_user工程Application类 

```java
	@Bean
	public JwtUtil jwtUtil(){
		return  new JwtUtil();
	}
```

+ 修改AdminController的login方法 

```java
    @Autowired
    private JwtUtil jwtUtil;
    /**
     * 登录
     * @return
     */
    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public Result login(@RequestBody Map<String, String> map) {
        Admin admin = adminService.findByLoginNameAndPassword(map.get("loginname"), map.get("password"));
		if(admin != null){
		    //登录成功,生成token
            String token = jwtUtil.createJWT(admin.getId(), admin.getLoginname(), "admin");
            Map resultMap=new HashMap();
            resultMap.put("token",token);
            resultMap.put("name",admin.getLoginname());//登陆名
            return new Result(true, StatusCode.OK, "登录成功",resultMap);
        }else{
            return new Result(true, StatusCode.LOGINERROR, "登录失败");
        }
    }
```

### 3.删除用户功能鉴权 

#### 3.1需求分析

​	==删除用户，必须是登录过的, 拥有管理员权限，否则不能删除。==

​	前后端约定：前端请求微服务时需要添加头信息, key为`Authorization` ,内容为 `Bearer+空格+token `

​	Authorization  : 授权的意思(HTTP协议里面默认的认证的请求头的key) 

​	Bearer: 持票人

#### 3.2代码实现

+ 修改UserController的delete方法 ，判断请求中的头信息，提取token并验证权限 

```java
 	@Autowired
    private JwtUtil jwtUtil;
    /**
     * 删除
     * @param id
     */
    @RequestMapping(value = "/{id}", method = RequestMethod.DELETE)
    public Result delete(@PathVariable String id, HttpServletRequest request) {

        String authorization = request.getHeader("Authorization");
        if(authorization == null){
            return new Result(false,StatusCode.ACCESSERROR,"权限不足");
        }

        if(!authorization.startsWith("Bearer ")){
            return new Result(false,StatusCode.ACCESSERROR,"权限不足");
        }

        String token = authorization.substring(7);
        Claims claims = jwtUtil.parseJWT(token);
  
        if(claims==null){
            return new Result(false,StatusCode.ACCESSERROR,"权限不足");
        }
        if(!"admin".equals(claims.get("roles"))){
            return new Result(false,StatusCode.ACCESSERROR,"权限不足");
        }

        userService.deleteById(id);
        return new Result(true, StatusCode.OK, "删除成功");
    }
```

### 4.使用拦截器方式实现token鉴权 

​	如果我们每个方法都去写一段代码，冗余度太高，不利于维护，那如何做使我们的代码看起来更清爽呢？我们可以将这段代码放入拦截器去实现 .

​	Spring为我们提供了HandlerInterceptor这个接口，实现此接口，可以非常方便的实现自己的拦截器。他有三个方法：分别实现预处理、后处理（调用了Service并返回ModelAndView，但未进行页面渲染）、返回处理（已经渲染了页面）
​	在preHandle中，可以进行编码、安全控制等处理；
​	在postHandle中，有机会修改ModelAndView；
​	在afterCompletion中，可以根据ex是否为null判断是否发生了异常，进行日志记录 

#### 4.1添加拦截器 

步骤:

1. 创建一个类实现HandlerInterceptor
2. 配置拦截器(ssm里面在配置文件里面配置; SpringBoot配置类)




+ 创建拦截器类。创建 com.tensquare.user.interceptor.JwtInterceptor

```java
@Component
public class JwtInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        System.out.println("JwtFilter 收到了请求...");
        return true;
    }
}
```

+ 配置拦截器类,创建com.tensquare.user.ApplicationConfig 继承==WebMvcConfigurationSupport==

```java
@Component
public class ApplicationConfig extends WebMvcConfigurationSupport {

    @Autowired
    private JwtInterceptor jwtInterceptor;

    @Override
    protected void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(jwtInterceptor).addPathPatterns("/**").excludePathPatterns("/**/login");
    }
}
```

#### 4.2拦截器验证token 

+ 修改JwtInterceptor

```java
@Component
public class JwtInterceptor implements HandlerInterceptor {

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String authorization = request.getHeader("Authorization");
        if (authorization != null && authorization.startsWith("Bearer")) {
            String token = authorization.substring(7);
            Claims claims = jwtUtil.parseJWT(token);
            if (claims != null) {
                if ("admin".equals(claims.get("roles"))) { //如果是管理员
                    request.setAttribute("admin_claims", claims);
                }
                if ("user".equals(claims.get("roles"))) { //如果是用户
                    request.setAttribute("user_claims", claims);
                }
            }
        }
        return true;
    }
}
```

+ 修改UserController

```java
    /**
     * 删除
     * @param id
     */
    @RequestMapping(value = "/{id}", method = RequestMethod.DELETE)
    public Result delete(@PathVariable String id, HttpServletRequest request) {

        Claims claims = (Claims) request.getAttribute("admin_claims");
        if(claims == null){
            return new Result(true,StatusCode.ACCESSERROR,"无权访问");
        }
        userService.deleteById(id);
        return new Result(true, StatusCode.OK, "删除成功");
    }
```

## 第六章-发布信息验证Token 

### 1.用户登陆签发 token

#### 1.1需求分析

​	用户登录成功后,签发token 响应给客户端. (返回token，昵称，头像等信息 )

#### 1.2代码实现

+ 修改UserController，引入JwtUtil 修改login方法

```java 
  /**
     * 登录
     * @return
     */
    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public Result login(@RequestBody Map<String, String> map) {
        User user = userService.findByMobileAndPassword(map.get("mobile"), map.get("password"));
        if (user != null) {
            //签发token
            String token = jwtUtil.createJWT(user.getId(), user.getMobile(), "user");

            Map resultMap = new HashMap();
            resultMap.put("token",token);
            resultMap.put("name",user.getNickname());//昵称
            resultMap.put("avatar",user.getAvatar());//头像

            return new Result(true, StatusCode.OK, "登录成功",resultMap);
        } else {
            return new Result(true, StatusCode.LOGINERROR, "登录失败");
        }
    }
```

### 2.发布问题功能鉴权 

#### 2.1需求分析

​	只有当用户登录了,并且 角色是 user 才可以发布问题

#### 2.2代码实现 

步骤:

1. 配置文件里面添加jwt配置(秘钥)
2. 把JwtUtil注册到Spring容器
3. 拷贝第五章tensquare_user里面的拦截器和拦截器的配置
4. 在ProblemController的add()方法里面进行判断



+ 修改tensquare_qa工程的QaApplication，增加bean 

```java
@SpringBootApplication
public class QaApplication {

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}
	...

	@Bean
	public JwtUtil jwtUtil(){
		return  new JwtUtil();
	}
	
}
```

+ tensquare_qa工程配置文件application.yml增加配置 

```yaml
jwt:
  config:
    key: itcast
    ttl: 3600000
```

+ 定义拦截器(拷贝第五章)

```
@Component
public class JwtInterceptor extends HandlerInterceptorAdapter {

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        System.out.println("JwtFilter 收到了请求...");
        String authorization = request.getHeader("Authorization");

        if(authorization != null && authorization.startsWith("Bearer ")){
            String token = authorization.substring(7);
            Claims claims = jwtUtil.parseJWT(token);
            if (claims != null) {
                if("admin".equals(claims.get("roles"))){//如果是管理员
                    request.setAttribute("admin_claims", claims);
                }
                if("user".equals(claims.get("roles"))){//如果是用户
                    request.setAttribute("user_claims", claims);
                }
            }
        }

        return true;
    }
}
```

+ 增加配置类ApplicationConfig （拷贝第五章） 

```
@Component
public class ApplicationConfig extends WebMvcConfigurationSupport {

    @Autowired
    private JwtInterceptor jwtInterceptor;

    @Override
    protected void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(jwtInterceptor)
                .addPathPatterns("/**")
                .excludePathPatterns("/**/login");
        ;
    }
}
```

+ 修改ProblemController的add()方法

```java
	/**
	 * 增加
	 * @param problem
	 */
	@RequestMapping(method=RequestMethod.POST)
	public Result add(@RequestBody Problem problem, HttpServletRequest request){
		Claims claims = (Claims) request.getAttribute("user_claims");
		if(claims == null){
			return new Result(false,StatusCode.ACCESSERROR,"无权访问");
		}
		problem.setUserid(claims.getId());
		problemService.add(problem);
		return new Result(true,StatusCode.OK,"增加成功");
	}
```

### 3.回答问题 ,发文章,活动功能鉴权 

+ 学员实现


## 总结

+ 项目里面有没有使用第三方登录

  ​	等学了前端课程的第6天 再准备

+ 之前的项目有没有和安卓,ios等客户端对接, 用户状态怎么处理的

  ​	token   

+ 载荷里面能存放敏感数据(密码)

  ​	不能放. 载荷通过Base64编码得到的字符串, Base64可以解码

+ 用户的密码采取的是什么加密方式? 常见的加密方式有哪些

  ​	MD5

  ​	SpringSecurity的BCryptPasswordEncoder

  ​	

  

  

  

  

  






