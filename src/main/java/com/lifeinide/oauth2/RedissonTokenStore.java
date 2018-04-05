package com.lifeinide.oauth2;

import org.redisson.api.RMap;
import org.redisson.api.RMapCache;
import org.redisson.api.RMultimap;
import org.redisson.api.RedissonClient;
import org.redisson.api.map.event.EntryExpiredListener;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.concurrent.TimeUnit;

/**
 * Redisson {@link TokenStore} based on {@link InMemoryTokenStore}.
 *
 * @author Lukasz Frankowski (lifeinide.com)
 */
public class RedissonTokenStore implements TokenStore {

	/**
	 * Defines inertia between token expiration in outh2 services and token expiration in redisson. Items in redisson should live a little
	 * longer than in oauth2 services to assert accessibility after oauth2 expiration time. On the other hand these items shouldn't live
	 * forever, because they would eat memory indefinetly.
	 */
	protected static final int TOKEN_EXPIRATION_INTERTIA_SECS = 600;

	protected RedissonClient redisson;

	protected RMapCache<String, OAuth2AccessToken> accessTokenStore;
	protected RMap<String, OAuth2AccessToken> authenticationToAccessTokenStore;
	protected RMap<String, String> accessTokenToRefreshTokenStore; 
	protected RMap<String, OAuth2Authentication> authenticationStore; 

	protected RMultimap<String, OAuth2AccessToken> clientIdToAccessTokenStore;
	protected RMultimap<String, OAuth2AccessToken> userNameToAccessTokenStore; 

	protected RMapCache<String, OAuth2RefreshToken> refreshTokenStore;
	protected RMap<String, OAuth2Authentication> refreshTokenAuthenticationStore;
	protected RMap<String, String> refreshTokenToAccessTokenStore;

	/**
	 * Creates token store instance.
	 * 
	 * @param redisson Redisson client
	 * @param keyPrefix Key prefix to be used to prefix keys in redis
	 */
	public RedissonTokenStore(RedissonClient redisson, String keyPrefix) {
		this.redisson = redisson;

		accessTokenStore = redisson.getMapCache(keyPrefix + "accessTokenStore");
		authenticationToAccessTokenStore = redisson.getMap(keyPrefix + "authenticationToAccessTokenStore");
		accessTokenToRefreshTokenStore = redisson.getMap(keyPrefix + "accessTokenToRefreshTokenStore");
		authenticationStore = redisson.getMap(keyPrefix + "authenticationStore");

		clientIdToAccessTokenStore = redisson.getSetMultimap(keyPrefix + "accessTokenStore");
		userNameToAccessTokenStore = redisson.getSetMultimap(keyPrefix + "userNameToAccessTokenStore");

		refreshTokenStore = redisson.getMapCache(keyPrefix + "refreshTokenStore");
		refreshTokenAuthenticationStore = redisson.getMap(keyPrefix + "refreshTokenAuthenticationStore");
		refreshTokenToAccessTokenStore = redisson.getMap(keyPrefix + "refreshTokenToAccessTokenStore");

		// expiration rules

		accessTokenStore.addListener((EntryExpiredListener<String, OAuth2AccessToken>) event -> {
			OAuth2Authentication authentication = authenticationStore.remove(event.getKey());
			if (authentication!=null) {
				String authenticationKey = authenticationKeyGenerator.extractKey(authentication);
				authenticationToAccessTokenStore.remove(authenticationKey);
				clientIdToAccessTokenStore.remove(authentication.getOAuth2Request().getClientId(), event.getValue());
				userNameToAccessTokenStore.remove(getApprovalKey(authentication), event.getValue());
			}
			accessTokenToRefreshTokenStore.remove(event.getKey());
		});

		refreshTokenStore.addListener((EntryExpiredListener<String, OAuth2RefreshToken>) event -> {
			refreshTokenAuthenticationStore.remove(event.getKey());
			refreshTokenToAccessTokenStore.remove(event.getKey());
		});
	}

	protected <V> V putToCache(String key, V value, RMapCache<String, V> cache) {
		Date expiration = null;
		if (value instanceof OAuth2AccessToken)
			expiration = ((OAuth2AccessToken) value).getExpiration();
		else if (value instanceof DefaultExpiringOAuth2RefreshToken)
			expiration = ((DefaultExpiringOAuth2RefreshToken) value).getExpiration();

		if (expiration==null) {
			return cache.put(key, value, 0, TimeUnit.SECONDS); // indefinetly
		} else
			return cache.put(key, value,
				Long.valueOf((expiration.getTime() - System.currentTimeMillis()) / 1000L).intValue()+TOKEN_EXPIRATION_INTERTIA_SECS,
				TimeUnit.SECONDS);
	}

	private AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();

	/**
	 * Convenience method for super admin users to remove all tokens (useful for testing, not really in production)
	 */
	public void clear() {
		accessTokenStore.clear();
		authenticationToAccessTokenStore.clear();
		clientIdToAccessTokenStore.clear();
		refreshTokenStore.clear();
		accessTokenToRefreshTokenStore.clear();
		authenticationStore.clear();
		refreshTokenAuthenticationStore.clear();
		refreshTokenToAccessTokenStore.clear();
	}

	@Override
	public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
		String key = authenticationKeyGenerator.extractKey(authentication);
		OAuth2AccessToken accessToken = authenticationToAccessTokenStore.get(key);
		if (accessToken != null && !key.equals(authenticationKeyGenerator.extractKey(readAuthentication(accessToken.getValue())))) {
			// Keep the stores consistent (maybe the same user is represented by this authentication but the details have changed)
			storeAccessToken(accessToken, authentication);
		}
		return accessToken;
	}

	@Override
	public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {
		return readAuthentication(token.getValue());
	}

	@Override
	public OAuth2Authentication readAuthentication(String token) {
		return this.authenticationStore.get(token);
	}

	@Override
	public OAuth2Authentication readAuthenticationForRefreshToken(OAuth2RefreshToken token) {
		return readAuthenticationForRefreshToken(token.getValue());
	}

	public OAuth2Authentication readAuthenticationForRefreshToken(String token) {
		return this.refreshTokenAuthenticationStore.get(token);
	}

	@Override
	public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
		putToCache(token.getValue(), token, this.accessTokenStore);
		this.authenticationStore.put(token.getValue(), authentication);
		this.authenticationToAccessTokenStore.put(authenticationKeyGenerator.extractKey(authentication), token);
		if (!authentication.isClientOnly()) {
			this.userNameToAccessTokenStore.put(getApprovalKey(authentication), token);
		}
		this.clientIdToAccessTokenStore.put(authentication.getOAuth2Request().getClientId(), token);
		if (token.getRefreshToken() != null && token.getRefreshToken().getValue() != null) {
			this.refreshTokenToAccessTokenStore.put(token.getRefreshToken().getValue(), token.getValue());
			this.accessTokenToRefreshTokenStore.put(token.getValue(), token.getRefreshToken().getValue());
		}
	}

	private String getApprovalKey(OAuth2Authentication authentication) {
		String userName = authentication.getUserAuthentication() == null ? "" : authentication.getUserAuthentication().getName();
		return getApprovalKey(authentication.getOAuth2Request().getClientId(), userName);
	}

	private String getApprovalKey(String clientId, String userName) {
		return clientId + (userName==null ? "" : ":" + userName);
	}

	@Override
	public void removeAccessToken(OAuth2AccessToken accessToken) {
		removeAccessToken(accessToken.getValue());
	}

	@Override
	public OAuth2AccessToken readAccessToken(String tokenValue) {
		return this.accessTokenStore.get(tokenValue);
	}

	public void removeAccessToken(String tokenValue) {
		OAuth2AccessToken removed = this.accessTokenStore.remove(tokenValue);
		this.accessTokenToRefreshTokenStore.remove(tokenValue);
		// Don't remove the refresh token - it's up to the caller to do that
		OAuth2Authentication authentication = this.authenticationStore.remove(tokenValue);
		if (authentication != null) {
			this.authenticationToAccessTokenStore.remove(authenticationKeyGenerator.extractKey(authentication));
			Collection<OAuth2AccessToken> tokens;
			String clientId = authentication.getOAuth2Request().getClientId();
			tokens = this.userNameToAccessTokenStore.get(getApprovalKey(clientId, authentication.getName()));
			if (tokens != null) {
				tokens.remove(removed);
			}
			tokens = this.clientIdToAccessTokenStore.get(clientId);
			if (tokens != null) {
				tokens.remove(removed);
			}
			this.authenticationToAccessTokenStore.remove(authenticationKeyGenerator.extractKey(authentication));
		}
	}

	@Override
	public void storeRefreshToken(OAuth2RefreshToken refreshToken, OAuth2Authentication authentication) {
		putToCache(refreshToken.getValue(), refreshToken, this.refreshTokenStore);
		this.refreshTokenAuthenticationStore.put(refreshToken.getValue(), authentication);
	}

	@Override
	public OAuth2RefreshToken readRefreshToken(String tokenValue) {
		return this.refreshTokenStore.get(tokenValue);
	}

	@Override
	public void removeRefreshToken(OAuth2RefreshToken refreshToken) {
		removeRefreshToken(refreshToken.getValue());
	}

	public void removeRefreshToken(String tokenValue) {
		this.refreshTokenStore.remove(tokenValue);
		this.refreshTokenAuthenticationStore.remove(tokenValue);
		this.refreshTokenToAccessTokenStore.remove(tokenValue);
	}

	@Override
	public void removeAccessTokenUsingRefreshToken(OAuth2RefreshToken refreshToken) {
		removeAccessTokenUsingRefreshToken(refreshToken.getValue());
	}

	private void removeAccessTokenUsingRefreshToken(String refreshToken) {
		String accessToken = this.refreshTokenToAccessTokenStore.remove(refreshToken);
		if (accessToken != null) {
			removeAccessToken(accessToken);
		}
	}

	@Override
	public Collection<OAuth2AccessToken> findTokensByClientIdAndUserName(String clientId, String userName) {
		Collection<OAuth2AccessToken> result = userNameToAccessTokenStore.get(getApprovalKey(clientId, userName));
		return result != null ? Collections.unmodifiableCollection(result) : Collections.emptySet();
	}

	@Override
	public Collection<OAuth2AccessToken> findTokensByClientId(String clientId) {
		Collection<OAuth2AccessToken> result = clientIdToAccessTokenStore.get(clientId);
		return result != null ? Collections.unmodifiableCollection(result) : Collections.emptySet();
	}

}
