/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.cas.authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.TicketValidationException;
import org.jasig.cas.client.validation.TicketValidator;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.cas.web.authentication.ServiceAuthenticationDetails;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation that integrates with JA-SIG Central
 * Authentication Service (CAS).
 * <p>
 * This <code>AuthenticationProvider</code> is capable of validating
 * {@link UsernamePasswordAuthenticationToken} requests which contain a
 * <code>principal</code> name equal to either
 * {@link CasAuthenticationFilter#CAS_STATEFUL_IDENTIFIER} or
 * {@link CasAuthenticationFilter#CAS_STATELESS_IDENTIFIER}. It can also validate a
 * previously created {@link CasAuthenticationToken}.
 *
 * @author Ben Alex
 * @author Scott Battaglia
 */
public class CasAuthenticationProvider implements AuthenticationProvider,
		InitializingBean, MessageSourceAware {
	// ~ Static fields/initializers
	// =====================================================================================

	private static final Log logger = LogFactory.getLog(CasAuthenticationProvider.class);

	// ~ Instance fields
	// ================================================================================================

	private AuthenticationUserDetailsService<CasAssertionAuthenticationToken> authenticationUserDetailsService;

	private final UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private StatelessTicketCache statelessTicketCache = new NullStatelessTicketCache();
	private String key;
	private TicketValidator ticketValidator;
	private ServiceProperties serviceProperties;
	private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

	// ~ Methods
	// ========================================================================================================

	public void afterPropertiesSet() {
		Assert.notNull(this.authenticationUserDetailsService,
				"An authenticationUserDetailsService must be set");
		Assert.notNull(this.ticketValidator, "A ticketValidator must be set");
		Assert.notNull(this.statelessTicketCache, "A statelessTicketCache must be set");
		Assert.hasText(
				this.key,
				"A Key is required so CasAuthenticationProvider can identify tokens it previously authenticated");
		Assert.notNull(this.messages, "A message source must be set");
	}

	public Authentication authenticate(Authentication authentication)
			throws AuthenticationException {
		if (!supports(authentication.getClass())) {
			return null;
		}

		//CasAuthenticationFilter创建的authentication为UsernamePasswordAuthenticationToken

		//如果是UsernamePasswordAuthenticationToken且用户名非cas指定则返回null表示当前Provider不支持
		//ProviderManager(循环)会交给下一个Provider处理
		if (authentication instanceof UsernamePasswordAuthenticationToken
				&& (!CasAuthenticationFilter.CAS_STATEFUL_IDENTIFIER
				.equals(authentication.getPrincipal().toString())
				&& !CasAuthenticationFilter.CAS_STATELESS_IDENTIFIER
				.equals(authentication.getPrincipal().toString()))) {
			// UsernamePasswordAuthenticationToken not CAS related
			return null;
		}

		// If an existing CasAuthenticationToken, just check we created it
		//如果是CasAuthenticationToken 且是key hash值相同 则认为认证成功
		if (authentication instanceof CasAuthenticationToken) {
			if (this.key.hashCode() == ((CasAuthenticationToken) authentication)
					.getKeyHash()) {
				return authentication;
			} else {
				throw new BadCredentialsException(
						messages.getMessage("CasAuthenticationProvider.incorrectKey",
								"The presented CasAuthenticationToken does not contain the expected key"));
			}
		}

		// Ensure credentials are presented
		// 如果请求不携带ticket 认为认证失败抛出异常 被ExceptionTranslationFilter捕获
		// 跳转到EntryPoint进行处理(可重定向到前端登陆页面让用户登陆/重定向到cas 服务端认证链接)
		if ((authentication.getCredentials() == null)
				|| "".equals(authentication.getCredentials())) {
			throw new BadCredentialsException(messages.getMessage(
					"CasAuthenticationProvider.noServiceTicket",
					"Failed to provide a CAS service ticket to validate"));
		}

		boolean stateless = false;

		//判断是否为无状态客户端
		if (authentication instanceof UsernamePasswordAuthenticationToken
				&& CasAuthenticationFilter.CAS_STATELESS_IDENTIFIER.equals(authentication
				.getPrincipal())) {
			stateless = true;
		}

		CasAuthenticationToken result = null;

		if (stateless) {
			// Try to obtain from cache
			// 如果是无状态客户端则从缓存中根据ticket获取Token
			result = statelessTicketCache.getByTicketId(authentication.getCredentials()
					.toString());
		}

		if (result == null) {
			//如果缓存中没有(无状态客户端)或是有状态客户端访问
			//授权信息为null则重新走cas服务器认证
			result = this.authenticateNow(authentication);
			//copy将http 请求信息 默认为ip和sessionId
			result.setDetails(authentication.getDetails());
		}

		if (stateless) {
			// Add to cache
			// 如果是无状态的客户端 则将新授权CasAuthenticationToken放入缓存
			statelessTicketCache.putTicketInCache(result);
		}

		return result;
	}

	private CasAuthenticationToken authenticateNow(final Authentication authentication)
			throws AuthenticationException {
		try {
			//发送http请求到cas服务认证并解析返回的xml为Assertion对象
			final Assertion assertion = this.ticketValidator.validate(authentication
					.getCredentials().toString(), getServiceUrl(authentication));
			//根据从cas拿到的Assertion加载用户详细信息
			//如当前服务的授权信息等
			final UserDetails userDetails = loadUserByAssertion(assertion);
			//判断用户状态 是否过期等
			userDetailsChecker.check(userDetails);
			//返回CAS认证后的Token
			return new CasAuthenticationToken(this.key, userDetails,
					authentication.getCredentials(),
					authoritiesMapper.mapAuthorities(userDetails.getAuthorities()),
					userDetails, assertion);
		} catch (final TicketValidationException e) {
			throw new BadCredentialsException(e.getMessage(), e);
		}
	}

	/**
	 * Gets the serviceUrl. If the {@link Authentication#getDetails()} is an instance of
	 * {@link ServiceAuthenticationDetails}, then
	 * {@link ServiceAuthenticationDetails#getServiceUrl()} is used. Otherwise, the
	 * {@link ServiceProperties#getService()} is used.
	 *
	 * @param authentication
	 * @return
	 */
	private String getServiceUrl(Authentication authentication) {
		String serviceUrl;
		if (authentication.getDetails() instanceof ServiceAuthenticationDetails) {
			serviceUrl = ((ServiceAuthenticationDetails) authentication.getDetails())
					.getServiceUrl();
		} else if (serviceProperties == null) {
			throw new IllegalStateException(
					"serviceProperties cannot be null unless Authentication.getDetails() implements ServiceAuthenticationDetails.");
		} else if (serviceProperties.getService() == null) {
			throw new IllegalStateException(
					"serviceProperties.getService() cannot be null unless Authentication.getDetails() implements ServiceAuthenticationDetails.");
		} else {
			serviceUrl = serviceProperties.getService();
		}
		if (logger.isDebugEnabled()) {
			logger.debug("serviceUrl = " + serviceUrl);
		}
		return serviceUrl;
	}

	/**
	 * Template method for retrieving the UserDetails based on the assertion. Default is
	 * to call configured userDetailsService and pass the username. Deployers can override
	 * this method and retrieve the user based on any criteria they desire.
	 *
	 * @param assertion The CAS Assertion.
	 * @return the UserDetails.
	 */
	protected UserDetails loadUserByAssertion(final Assertion assertion) {
		final CasAssertionAuthenticationToken token = new CasAssertionAuthenticationToken(
				assertion, "");
		return this.authenticationUserDetailsService.loadUserDetails(token);
	}

	@SuppressWarnings("unchecked")
	/**
	 * Sets the UserDetailsService to use. This is a convenience method to invoke
	 */
	public void setUserDetailsService(final UserDetailsService userDetailsService) {
		this.authenticationUserDetailsService = new UserDetailsByNameServiceWrapper(
				userDetailsService);
	}

	public void setAuthenticationUserDetailsService(
			final AuthenticationUserDetailsService<CasAssertionAuthenticationToken> authenticationUserDetailsService) {
		this.authenticationUserDetailsService = authenticationUserDetailsService;
	}

	public void setServiceProperties(final ServiceProperties serviceProperties) {
		this.serviceProperties = serviceProperties;
	}

	protected String getKey() {
		return key;
	}

	public void setKey(String key) {
		this.key = key;
	}

	public StatelessTicketCache getStatelessTicketCache() {
		return statelessTicketCache;
	}

	protected TicketValidator getTicketValidator() {
		return ticketValidator;
	}

	public void setMessageSource(final MessageSource messageSource) {
		this.messages = new MessageSourceAccessor(messageSource);
	}

	public void setStatelessTicketCache(final StatelessTicketCache statelessTicketCache) {
		this.statelessTicketCache = statelessTicketCache;
	}

	public void setTicketValidator(final TicketValidator ticketValidator) {
		this.ticketValidator = ticketValidator;
	}

	public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		this.authoritiesMapper = authoritiesMapper;
	}

	public boolean supports(final Class<?> authentication) {
		return (UsernamePasswordAuthenticationToken.class
				.isAssignableFrom(authentication))
				|| (CasAuthenticationToken.class.isAssignableFrom(authentication))
				|| (CasAssertionAuthenticationToken.class
				.isAssignableFrom(authentication));
	}
}
