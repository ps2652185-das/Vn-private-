import twilio from 'twilio';

/**
 * Real telephony adapter.
 * Credentials only from environment variables.
 */
export class TwilioProvider {
  constructor() {
    const sid = process.env.TWILIO_ACCOUNT_SID;
    const token = process.env.TWILIO_AUTH_TOKEN;
    if (!sid || !token) throw new Error('Twilio credentials are not configured');
    this.client = twilio(sid, token);
    this.country = process.env.TWILIO_COUNTRY || 'US';
    this.type = process.env.TWILIO_NUMBER_TYPE || 'local';
    this.areaCode = process.env.TWILIO_AREA_CODE || undefined;
  }

  async listAvailableNumbers() {
    const api = this.client.availablePhoneNumbers(this.country);
    let resource = this.type === 'mobile' ? api.mobile : api.local;
    const opts = { smsEnabled: true, voiceEnabled: true, limit: 30 };
    if (this.areaCode) opts.areaCode = this.areaCode;
    const list = await resource.list(opts);
    return list.map(n => ({
      phoneNumber: n.phoneNumber,
      country: this.country,
      providerNumberId: null,
      capabilities: n.capabilities || {}
    }));
  }

  async assignNumber(phoneNumber) {
    const created = await this.client.incomingPhoneNumbers.create({ phoneNumber });
    return {
      phoneNumber: created.phoneNumber,
      country: this.country,
      providerNumberId: created.sid
    };
  }

  async releaseNumber(providerNumberId) {
    await this.client.incomingPhoneNumbers(providerNumberId).remove();
  }

  async configureNumber(providerNumberId, voiceUrl, smsUrl) {
    await this.client.incomingPhoneNumbers(providerNumberId).update({
      voiceUrl,
      voiceMethod: 'POST',
      smsUrl,
      smsMethod: 'POST'
    });
  }

  async makeCall(from, to, statusCallback, answerUrl) {
    const call = await this.client.calls.create({
      from,
      to,
      url: answerUrl,
      method: 'POST',
      statusCallback,
      statusCallbackMethod: 'POST',
      statusCallbackEvent: ['initiated', 'ringing', 'answered', 'completed']
    });
    return { status: 'initiated', providerCallId: call.sid, mock: false };
  }

  async sendSms(from, to, body, statusCallback) {
    const message = await this.client.messages.create({
      from,
      to,
      body,
      statusCallback
    });
    return { status: message.status || 'queued', providerMessageId: message.sid, mock: false };
  }
}
