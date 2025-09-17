import { EmailMessage } from 'cloudflare:email';
import { createMimeMessage } from 'mimetext';

// 类型定义
type Env = {
	CUSTODY: D1Database;			//D1绑定
	ALLOWED_EMAILS?: string;	//允许的邮箱列表，形如a@x.com;b@y.com
};

type TDSecurity = {
	cusip: string;
	issueDate: string;				// ISO-like string
	maturityDate?: string;
	auctionDate?: string;
	highDiscountRate?: string;
	highInvestmentRate?: string;
	highPrice?: string;
	[k: string]: unknown;
};


export default {
	async email(message: ForwardableEmailMessage, env: Env, ctx: ExecutionContext): Promise<void> {
		const from: string = message.from || '';
		const subject: string = message.headers.get('subject') || '';
		const allowed_emails: Set<string> = parseAllowEmails(env.ALLOWED_EMAILS);
		const isAllowed: boolean = allowed_emails.has(normalizeEmail(from));

		if (!isAllowed) {
			await log(env.CUSTODY, from, env.ALLOWED_EMAILS ?? '', subject, 'Unauthorized access');
			return;
		}

		const isins: string[] = subject.split('/').map(s => s.trim()).filter(Boolean);
		if (isins.length === 0) {
			await log(env.CUSTODY, from, env.ALLOWED_EMAILS ?? '', subject, 'Invalid subject');
			return;
		}
		await log(env.CUSTODY, from, env.ALLOWED_EMAILS ?? '', subject, 'Authorized access and processed');

		//提取CUSIP
		const validCusips: string[] = isins.map(c => extractCusip(c)).filter((c): c is string => c !== null);

		if (validCusips.length === 0) {
			await log(env.CUSTODY, from, env.ALLOWED_EMAILS ?? '', subject, 'Invalid ISIN');
			return;
		}

		//进入生成邮件正文
		//邮件正文表头
		const header: string = ['cusip', 'issueDate', 'maturityDate', 'auctionDate', 'highDiscountRate', 'highInvestmentRate', 'highPrice'].join('\t');

		const contents: string[] = [header];

		// 获取 TDSecurity
		const securityPromises = validCusips.map(async (cusip) => {
			const security = await fecthTDSecurity(cusip, env.CUSTODY);
			return { cusip, security };
		});

		// 分批处理，避免过多并发请求
		const batchSize = 3; // 每批最多3个并发请求
		const securityResults: Array<{ cusip: string; security: TDSecurity | null }> = [];

		for (let i = 0; i < securityPromises.length; i += batchSize) {
			const batch = securityPromises.slice(i, i + batchSize);
			const batchResults = await Promise.all(batch);
			securityResults.push(...batchResults);

			// 批次间稍作延迟，避免请求过于频繁
			if (i + batchSize < securityPromises.length) {
				await new Promise(resolve => setTimeout(resolve, 1000));
			}
		}

		// 处理结果并准备数据库批量写入
		const detailsToLog: Array<{ from: string; subject: string; detail: TDSecurity }> = [];

		for (const { cusip, security } of securityResults) {
			if (!security) {
				await log(env.CUSTODY, from, env.ALLOWED_EMAILS ?? '', subject, `Failed to fetch CUSIP ${cusip}`);
				contents.push(`${cusip}\tFailed to fetch data`);
				continue;
			}

			detailsToLog.push({ from, subject, detail: security });
			contents.push([
				security.cusip ?? cusip,
				security.issueDate ?? '',
				security.maturityDate ?? '',
				security.auctionDate ?? '',
				security.highDiscountRate ?? '',
				security.highInvestmentRate ?? '',
				security.highPrice ?? ''
			].join('\t'));
		}

		// 修改：批量写入详细信息到数据库，而非循环中单独写入
		if (detailsToLog.length > 0) {
			await logDetailsBatch(env.CUSTODY, detailsToLog);
		}

		// 只发送一次邮件，包含所有结果
		const body: string = contents.join('\n');
		await sendReply(message, env, from, subject, body);
	}
} satisfies ExportedHandler<Env>;

// 邮箱字母全部改为小写字母
function normalizeEmail(e: string): string {
	return e.trim().toLowerCase();
}

// 从ALLOWED_EMAILS别表获取允许的邮箱地址列表
function parseAllowEmails(raw?: string): Set<string> {
	if (!raw) return new Set();
	return new Set(
		raw.split(';').map(s => s.trim()).filter(Boolean).map(normalizeEmail)
	);
}

// 将日志数据写入log数据库
async function log(db: D1Database, sender_email: string, allowed_emails: string, subject: string, error_msg: string): Promise<void> {
	try {
		await db.prepare(
			`INSERT INTO cusip_logs (logged_at, sender_email, allowed_emails, subject, error_msg)
			 VALUES (CURRENT_TIMESTAMP, ?, ?, ?, ?)`
		).bind(sender_email, allowed_emails, subject, error_msg).run();
	} catch (e) {
		console.error('Failed to log unauthorized access:', e);
	}
}

// 从isin代码获取cusip代码
// isin码：前2位国家代码 + 9位CUSIP + 1位校验位 = 共12位
function extractCusip(isin?: string): string | null {
	if (!isin) return null;

	const clean_isin = isin.replace(/[^0-9A-Za-z]/g, '');
	// 修复：ISIN标准长度应该是12位，不是11位
	if (clean_isin.length !== 12) return null;

	// 提取第3-11位作为CUSIP（9位）
	const cusip = clean_isin.slice(2, 11);
	return cusip.length === 9 ? cusip : null;
}

// 基于 fetch 函数逻辑的直接调用函数
async function fecthTDSecurity(cusip: string, db?: D1Database, retries: number = 3): Promise<TDSecurity | null> {
	for (let attempt = 0; attempt <= retries; attempt++) {
		try {
			// 拼接拉去的 URL
			const apiUrl = `https://td.echopath.one/?cusip={cusip}`;

			// 根据充实次数调整超时时间： 15秒 -> 22秒 -> 30秒 -> 37秒
			const timeoutMs: number = 15000 + (attempt * 7500);

			// 模拟 chrome 浏览器的 headers
			const response: Response = await fetch(apiUrl, {
				method: 'GET',
				headers: {
					'Accept': 'application/json',
					'User-Agent': 'Mozilla/5.0 (compatible; CUSIP-Service/1.0)'
				},
				// 设置超时时间
				signal: AbortSignal.timeout(timeoutMs)
			});

			// 检查 HTTP 状态
			if (!response.ok) {
				const errorMsg: string = `Failed to fetch TDSecurity data. Status: ${response.status}, StatusText: ${response.statusText}`;

				// 如果是最后一次尝试，则将错误记录到数据库
				if (attempt === retries && db) {
					await log(db, 'system', '', cusip, `${errorMsg} (after ${retries + 1} attempts)`);
				}

				// 对于 5xx 错误或者 429 限流进行重试，4xx错误直接返回
				if ((response.status >= 500 || response.status === 429) && attempt < retries) {
					const delayMs = Math.min(2000 * Math.pow(2, attempt), 10000); // 指数退避，最大10秒
					await new Promise(resolve => setTimeout(resolve, delayMs));
					continue;
				}
				return null;
			}

			// 解析 JSON 响应
			const data = await response.json();

			// 检查是否返回有效值
			if (!Array.isArray(data) || data.length === 0) {
				const errorMsg: string = `No security data found for CUSIP ${cusip}`;
				if (db) {
					await log(db, 'system', '', cusip, errorMsg);
				}
				return null;
			}

			// 如果有多个数值，返回 issueDate 最大的记录
			const latestSecurity: TDSecurity = data.reduce((latest, current) => {
				const currentIssueDate: Date = new Date(current.issueDate);
				const latestIssueDate: Date = new Date(latest.issueDate);
				return currentIssueDate > latestIssueDate ? current : latest;
			});

			// 构建 TDSecurity 对象
			const tdSecurity: TDSecurity = {
				cusip: latestSecurity.cusip || cusip,
				issueDate: latestSecurity.issueDate || '',
				maturityDate: latestSecurity.maturityDate || undefined,
				auctionDate: latestSecurity.auctionDate || undefined,
				highDiscountRate: latestSecurity.highDiscountRate || undefined,
				highInvestmentRate: latestSecurity.highInvestmentRate || undefined,
				highPrice: latestSecurity.highPrice || undefined,
				// 保留原始数据的所有字段
				...latestSecurity
			};

			return tdSecurity;
		} catch (error) {
			// 对于超时和网络错误进行重试
			const isRetryableError: boolean = error instanceof Error && (error.name === 'AbortError' || error.message.includes('timeout') || error.message.includes('network'));

			if (isRetryableError && attempt < retries) {
				const delayMs: number = Math.min(2000 * Math.pow(2, attempt), 10000); // 指数退避
				await new Promise(resolve => setTimeout(resolve, delayMs));
				continue;
			}

			// 记录最终错误
			let errorMsg: string;
			if (error instanceof Error) {
				errorMsg = `Error fetching CUSIP ${cusip}: ${error.message} (after ${attempt + 1} attempts)`;
			} else {
				errorMsg = `Unknown error fetching CUSIP ${cusip}: ${String(error)} (after ${attempt + 1} attempts)`;
			}

			if (db) {
				await log(db, 'system', '', cusip, errorMsg);
			}
			return null;
		}
	}

	return null;
}

// 批量将TDSecurity写入数据库
async function logDetailsBatch(db: D1Database, details: Array<{
	from: string;
	subject: string;
	detail: TDSecurity
}>): Promise<void> {
	if (details.length === 0) return;

	try {
		// 构建批量插入语句
		const values = details.map(() => '(CURRENT_TIMESTAMP, ?, ?, ?, ?)').join(', ');
		const sql = `INSERT INTO cusip_detail(logged_at, sender_email, subject, cusip, detail_json)
								 VALUES ${values}`;

		// 构建参数数组
		const params: string[] = [];
		for (const { from, subject, detail } of details) {
			params.push(from, subject, detail.cusip ?? '', JSON.stringify(detail));
		}

		await db.prepare(sql).bind(...params).run();
	} catch (e) {
		// 如果批量插入失败，退回到单独插入
		console.warn('Batch insert failed, falling back to individual inserts:', e);
		const insertPromises = details.map(({ from, subject, detail }) =>
			logDetail(db, from, subject, detail)
		);
		await Promise.all(insertPromises);
	}
}

// 回复邮件（增强错误处理和认证支持）
async function sendReply(message: ForwardableEmailMessage, env: Env, from: string, subject: string, body: string): Promise<void> {
	try {
		const msg = createMimeMessage();
		msg.setSender({ name: 'CUSIP Service', addr: 'cusip@qujing.eu.org' });
		msg.setRecipient(from);
		msg.setSubject(`Re: ${subject}`);

		// 设置更完整的邮件头
		const messageId = message.headers.get('Message-ID') || message.headers.get('message-id');
		if (messageId) {
			msg.setHeader('In-Reply-To', messageId);
			msg.setHeader('References', messageId);
		}

		// 添加日期头
		msg.setHeader('Date', new Date().toUTCString());

		// 设置MIME版本
		msg.setHeader('MIME-Version', '1.0');

		msg.addMessage({ contentType: 'text/plain', data: body });

		const replyMessage = new EmailMessage('cusip@qujing.eu.org', from, msg.asRaw());

		// 尝试使用reply方法
		try {
			await message.reply(replyMessage);

			// 成功发送，记录到队列表
			await env.CUSTODY.prepare(
				`INSERT INTO cusip_email_queue(created_at, recipient, subject, body, status, sent_at, error_message)
				 VALUES (CURRENT_TIMESTAMP, ?, ?, ?, 'sent', CURRENT_TIMESTAMP, NULL)`
			).bind(from, `Re: ${subject}`, body).run();

		} catch (replyError) {
			// reply失败，尝试直接发送
			if (replyError instanceof Error && replyError.message.includes('not authenticated')) {
				await sendDirectEmail(env, from, subject, body);
			} else {
				throw replyError; // 重新抛出其他错误
			}
		}

	} catch (e) {
		await log(env.CUSTODY, from, env.ALLOWED_EMAILS ?? '', subject, `Failed to send reply: ${e instanceof Error ? e.message : String(e)}`);

		try {
			await env.CUSTODY.prepare(
				`INSERT INTO cusip_email_queue(created_at, recipient, subject, body, status, sent_at, error_message)
				 VALUES (CURRENT_TIMESTAMP, ?, ?, ?, 'failed', CURRENT_TIMESTAMP, ?)`
			).bind(from, `Re: ${subject}`, body, `Send error: ${e instanceof Error ? e.message : String(e)}`).run();
		} catch (dberror) {
			await log(env.CUSTODY, from, env.ALLOWED_EMAILS ?? '', subject, `Failed to log failed reply: ${dberror instanceof Error ? dberror.message : String(dberror)}`);
		}
	}
}

// 直接发送邮件的备用方法
async function sendDirectEmail(env: Env, to: string, originalSubject: string, body: string): Promise<void> {
	try {
		const msg = createMimeMessage();
		msg.setSender({ name: 'CUSIP Service', addr: 'cusip@qujing.eu.org' });
		msg.setRecipient(to);
		msg.setSubject(`Re: ${originalSubject}`);
		msg.setHeader('Date', new Date().toUTCString());
		msg.setHeader('MIME-Version', '1.0');
		msg.addMessage({ contentType: 'text/plain', data: body });

		// 创建新的邮件消息（不是回复）
		const directMessage = new EmailMessage('cusip@qujing.eu.org', to, msg.asRaw());

		// 这里需要根据您的Cloudflare配置调整
		// 如果有邮件发送API，请在此处调用
		// 暂时记录为待处理状态
		await env.CUSTODY.prepare(
			`INSERT INTO cusip_email_queue(created_at, recipient, subject, body, status, sent_at, error_message)
			 VALUES (CURRENT_TIMESTAMP, ?, ?, ?, 'pending', NULL, 'Direct send attempted')`
		).bind(to, `Re: ${originalSubject}`, body).run();

	} catch (e) {
		await log(env.CUSTODY, to, '', originalSubject, `Direct email send failed: ${e instanceof Error ? e.message : String(e)}`);
	}
}

// 将TDSecurity 写入数据库
async function logDetail(db: D1Database, from: string, subject: string, detail: TDSecurity): Promise<void> {
	try {
		await db.prepare(
			`INSERT INTO cusip_detail(logged_at, sender_email, subject, cusip, detail_json)
			 VALUES (CURRENT_TIMESTAMP, ?, ?, ?, ?)`
		).bind(from, subject, detail.cusip ?? '', JSON.stringify(detail)).run();
	} catch (e) {
		await log(db, from, '', subject, `Failed to log detail: ${e instanceof Error ? e.message : String(e)}`);
	}
}
