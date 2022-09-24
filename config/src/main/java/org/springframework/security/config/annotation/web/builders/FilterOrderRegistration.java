/*
 * Copyright 2002-2021 the original author or authors.
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
package org.springframework.security.config.annotation.web.builders;

import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.Filter;

import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.security.web.authentication.switchuser.SwitchUserFilter;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.authentication.ui.DefaultLogoutPageGeneratingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.security.web.jaasapi.JaasApiIntegrationFilter;
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.web.filter.CorsFilter;

/**
 * An internal use only {@link Comparator} that sorts the Security {@link Filter}
 * instances to ensure they are in the correct order.
 *
 * @author Rob Winch
 * @since 3.2
 */
final class FilterOrderRegistration {
	private static final int INITIAL_ORDER = 100;
	private static final int ORDER_STEP = 100;
	private final Map<String, Integer> filterToOrder = new HashMap<>();

	FilterOrderRegistration() {
		Step order = new Step(INITIAL_ORDER, ORDER_STEP);
		put(ChannelProcessingFilter.class, order.next());
		// 可以让用户拥有多个Session
		// 检查Session是否过期，并在过期后执行对应策略 如调用LogOutHandler执行注销操作
		put(ConcurrentSessionFilter.class, order.next());
		//将 WebAsyncManger 与 SpringSecurity 上下文进行集成
		put(WebAsyncManagerIntegrationFilter.class, order.next());
		//先创建安全认证上下文  并在认证成功(其他Filter执行结束后)后持久化认证信息 默认是保存到Session
		put(SecurityContextPersistenceFilter.class, order.next());
		//添加Header到当前Response,默认在其他过滤器执行结束后添加 可配置先添加Header在执行过滤器
		//添加Header内容可配置，配置方式为向headerWriters添加HeaderWriter
		put(HeaderWriterFilter.class, order.next());
		//是否允许跨域资源共享 如收到跨域请求时set cookie
		//Cors:一份浏览器技术的规范
		//	   提供了 Web 服务从不同网域传来沙盒脚本的方法，以避开浏览器的(samesite)同源策略(只有在相同域名下才可以携带cookie)
		//根据配置的CorsConfigurationSource执行Cors策略
		//校验Header及预检请求信息 校验合格则设置Cors规范的Header 然后执行后续Filter
		put(CorsFilter.class, order.next());
		//是否开启跨域请求伪造
		put(CsrfFilter.class, order.next());
		//如果满足注销条件 注销Filter，调用所有登记的LogoutHandler 并在注销成功后调用LogoutSuccessHandler
		//不满足注销条件  执行后续Filter
		put(LogoutFilter.class, order.next());
		//特殊的Filter 在执行认证前读request进行加工或拦截重定向等操作
		filterToOrder.put(
			"org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter",
				order.next());
		filterToOrder.put(
				"org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationRequestFilter",
				order.next());
		//预登录认证Filter，认证已在其他系统完成 不需要SpringSecurity再执行认证操作时配置
		//一般此时SpringSecurity此时只需要做补充授权信息和权限管控即可
		put(X509AuthenticationFilter.class, order.next());
		put(AbstractPreAuthenticatedProcessingFilter.class, order.next());
		//-----------以下为执行认证操作的Filter 一般多选一
		//response会被SaveContextOnUpdateOrErrorResponseWrapper封装 如果进行重定向等操作会调用saveContext
		//默认保存到Session中
		//！！！注意SessionAuthenticationStrategy策略 一定要配置 否则认证信息不会保存到Session中
		//配置CasFilter
		filterToOrder.put("org.springframework.security.cas.web.CasAuthenticationFilter",
				order.next());
		filterToOrder.put(
			"org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter",
				order.next());
		filterToOrder.put(
				"org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter",
				order.next());
		//用户名密码认证 如果配置了FormLogin则自动添加此Filter
		put(UsernamePasswordAuthenticationFilter.class, order.next());
		//校验Session信息 此处重复添加覆盖了之前的排序位置 目的是？
		put(ConcurrentSessionFilter.class, order.next());
		filterToOrder.put(
				"org.springframework.security.openid.OpenIDAuthenticationFilter", order.next());
		//生成Login页面
		put(DefaultLoginPageGeneratingFilter.class, order.next());
		//生成logout页面
		put(DefaultLogoutPageGeneratingFilter.class, order.next());
		put(ConcurrentSessionFilter.class, order.next());
		//摘要认证
		put(DigestAuthenticationFilter.class, order.next());
		filterToOrder.put(
				"org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter", order.next());
		//基础认证 如果其他认证过滤器成功则不执行逻辑 直接进入下一个过滤器
		put(BasicAuthenticationFilter.class, order.next());

		//缓存请求
		put(RequestCacheAwareFilter.class, order.next());
		//针对ServletRequest进行了一次包装，使得request具有更加丰富的API
		put(SecurityContextHolderAwareRequestFilter.class, order.next());
		//Jaas认证过滤器 早起的java安全认证框架
		put(JaasApiIntegrationFilter.class, order.next());

		//RememberMe功能实现,可配置 默认不添加
		//如果Context中获取不到Authentication 则使用RememberMe生成的Token进行验证
		//如果能获取到 则不执行  直接进入下一步
		put(RememberMeAuthenticationFilter.class, order.next());
		//匿名认证 如果Context中Authentication为空，则生成一个AnonymousAuthenticationToken
		//不为空直接执行下一步
		//执行到此过滤器为空的情况 请求不满足认证过滤器的认证条件(如url未命中)，所以没执行认证操作
		//AnonymousAuthenticationToken会被ExceptionTranslationFilter处理并进入AuthenticationEntryPoint
		//AuthenticationEntryPoint可以实现转发等逻辑 将请求转发到登录页面(认证接口)让用户进行登录
		put(AnonymousAuthenticationFilter.class, order.next());
		filterToOrder.put(
			"org.springframework.security.oauth2.client.web.OAuth2AuthorizationCodeGrantFilter",
				order.next());
		//Session管理 判断Session是否过期等
		put(SessionManagementFilter.class, order.next());
		//异常转换 如果时认证/权限异常则进入AuthenticationEntryPoint
		put(ExceptionTranslationFilter.class, order.next());
		//权限管控拦截器 拦截http访问的资源 检查是否符合Secured注解配置
		//对应有MethodSecurityInterceptor 方法拦截需要开启prepost注解才会生效
		put(FilterSecurityInterceptor.class, order.next());
		//用户切换拦截器
		put(SwitchUserFilter.class, order.next());
	}

	/**
	 * Register a {@link Filter} with its specific position. If the {@link Filter} was
	 * already registered before, the position previously defined is not going to be
	 * overriden
	 * @param filter the {@link Filter} to register
	 * @param position the position to associate with the {@link Filter}
	 */
	void put(Class<? extends Filter> filter, int position) {
		String className = filter.getName();
		if (this.filterToOrder.containsKey(className)) {
			return;
		}
		this.filterToOrder.put(className, position);
	}

	/**
	 * Gets the order of a particular {@link Filter} class taking into consideration
	 * superclasses.
	 *
	 * @param clazz the {@link Filter} class to determine the sort order
	 * @return the sort order or null if not defined
	 */
	Integer getOrder(Class<?> clazz) {
		while (clazz != null) {
			Integer result = filterToOrder.get(clazz.getName());
			if (result != null) {
				return result;
			}
			clazz = clazz.getSuperclass();
		}
		return null;
	}

	private static class Step {

		private int value;
		private final int stepSize;

		Step(int initialValue, int stepSize) {
			this.value = initialValue;
			this.stepSize = stepSize;
		}

		int next() {
			int value = this.value;
			this.value += this.stepSize;
			return value;
		}

	}

}
