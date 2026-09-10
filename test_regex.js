const block = `from mail.google.com (mail.google.com. [209.85.220.65])
        by mx.google.com with ESMTPS id abcdef12345
        for <recipient@example.com>;
        Thu, 10 Sep 2026 12:00:05 -0700 (PDT)`;
const fromM = block.match(/from\s+([^\s\(\[]+)/i);
console.log("from:", fromM ? fromM[1] : null);
const byM = block.match(/by\s+([^\s\(\[;]+)/i);
console.log("by:", byM ? byM[1] : null);
