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

		const contents:string[]=[header]

		// TODO

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
