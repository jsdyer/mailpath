export const SAMPLE = `Received: from relay.example.net (relay.example.net [203.0.113.42])
 by inbox.example.com with ESMTPS; Mon, 16 Nov 2026 12:00:18 +0000
Authentication-Results: inbox.example.com;
 spf=pass smtp.mailfrom=bounce@sender.example;
 dkim=pass header.d=sender.example; dmarc=pass header.from=sender.example
Received: from outbound.sender.example ([2001:db8::28])
 by relay.example.net with ESMTPS; Mon, 16 Nov 2026 12:00:10 +0000
Received: from client.example.org (client.example.org [198.51.100.31])
 by outbound.sender.example with ESMTPSA; Mon, 16 Nov 2026 12:00:00 +0000
DKIM-Signature: v=1; d=sender.example; s=sample; b=synthetic-not-a-signature
From: Sample sender <someone@sender.example>
To: Sample recipient <someone@inbox.example.com>
Subject: Synthetic relay trace`;
