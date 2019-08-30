package a;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.embedded.ConfigurableEmbeddedServletContainer;
import org.springframework.boot.context.embedded.EmbeddedServletContainerCustomizer;
import org.springframework.boot.web.support.SpringBootServletInitializer;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Date;

@Controller
@SpringBootApplication
@RequestMapping( "/api/v1/" )
public class TblogApplication
                extends SpringBootServletInitializer
                implements EmbeddedServletContainerCustomizer
{

    @RequestMapping( value = "/get/code", method = RequestMethod.GET )
    @ResponseBody
    public String GetCode()
    {
        try
        {
            SecureRandom secureRandom = SecureRandom.getInstance( "SHA1PRNG" );
            return String.valueOf( secureRandom.nextInt() );
        }
        catch ( NoSuchAlgorithmException e )
        {
            e.printStackTrace();
        }
        return "";
    }

    @RequestMapping( value = "/get/token", method = RequestMethod.GET )
    @ResponseBody
    public String GetToken( String name, String pwd, String code )
    {
        return createJwtToken( name, pwd, code );
    }

    @RequestMapping( value = "/get/oauth", method = RequestMethod.GET )
    @ResponseBody
    public Claims GetOauth( String token )
    {
        Claims ob = null;
        try
        {
            ob = parseJWT( token );
        }
        catch ( Exception e )
        {
            return null;
            //e.printStackTrace();
        }

        return ob;
    }

    /**
     * 签名秘钥
     */
    public static final String SECRET = "admin";

    /**
     * 生成token
     *
     * @param name 一般传入userName
     * @return
     */
    public static String createJwtToken( String name, String pwd, String code )
    {
        long ttlMillis = 3600000;
        return createJwtToken( name, pwd, code, ttlMillis );
    }

    /**
     * 生成Token
     *
     * @param id        编号
     * @param issuer    该JWT的签发者，是否使用是可选的
     * @param subject   该JWT所面向的用户，是否使用是可选的；
     * @param ttlMillis 签发时间 （有效时间，过期会报错）
     * @return token String
     */
    public static String createJwtToken( String id, String issuer, String subject, long ttlMillis )
    {

        // 签名算法 ，将对token进行签名
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

        // 生成签发时间
        long nowMillis = System.currentTimeMillis();
        Date now = new Date( nowMillis );

        // 通过秘钥签名JWT
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary( SECRET );
        Key signingKey = new SecretKeySpec( apiKeySecretBytes, signatureAlgorithm.getJcaName() );

        // Let's set the JWT Claims
        JwtBuilder builder = Jwts.builder().setId( id )
                                 .setIssuedAt( now )
                                 .setSubject( subject )
                                 .setIssuer( issuer )
                                 .signWith( signatureAlgorithm, signingKey );

        // if it has been specified, let's add the expiration
        if ( ttlMillis >= 0 )
        {
            long expMillis = nowMillis + ttlMillis;
            Date exp = new Date( expMillis );
            builder.setExpiration( exp );
        }

        // Builds the JWT and serializes it to a compact, URL-safe string
        return builder.compact();

    }

    // Sample method to validate and read the JWT
    public static Claims parseJWT( String jwt )
    {
        // This line will throw an exception if it is not a signed JWS (as expected)
        Claims claims = Jwts.parser()
                            .setSigningKey( DatatypeConverter.parseBase64Binary( SECRET ) )
                            .parseClaimsJws( jwt ).getBody();
        return claims;
    }

    @Override
    protected SpringApplicationBuilder configure( SpringApplicationBuilder builder )
    {
        return builder.sources( TblogApplication.class );
    }

    @Override
    public void customize( ConfigurableEmbeddedServletContainer configurableEmbeddedServletContainer )
    {
        //指定端口地址
        configurableEmbeddedServletContainer.setPort( 8082 );

    }

    public static void main( String[] args )
    {
        SpringApplication.run( TblogApplication.class, args );
    }
}
