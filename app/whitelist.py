"""Allowlist of explicit hostnames for the root-URL reputation fast path."""

from urllib.parse import urlsplit

GLOBAL_TRUSTED_DOMAINS = {
    "apple.com", "amazon.com", "archive.org", "atlassian.com", "cloudflare.com",
    "comptia.org", "debian.org", "docker.com", "facebook.com", "github.com",
    "gitlab.com", "google.com", "hackthebox.com", "linkedin.com", "microsoft.com",
    "mozilla.org", "netflix.com", "openai.com", "owasp.org", "paypal.com",
    "sans.org", "splunk.com", "stackoverflow.com", "tryhackme.com", "ubuntu.com",
    "virustotal.com", "wikipedia.org", "youtube.com",
}

INDIAN_TRUSTED_DOMAINS = {
    "onlinesbi.sbi", "sbi.co.in", "sbicard.com", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "kotak.com", "pnbindia.in", "bankofbaroda.in", "canarabank.com", "unionbankofindia.co.in",
    "indusind.com", "yesbank.in", "idfcfirstbank.com", "federalbank.co.in", "rbi.org.in",
    "npci.org.in", "bhimupi.org.in", "paytm.com", "phonepe.com", "gpay.app", "razorpay.com",
    "cashfree.com", "payu.in", "billdesk.com", "ccavenue.com", "groww.in", "zerodha.com",
    "upstox.com", "angelone.in", "nseindia.com", "bseindia.com", "sebi.gov.in", "irctc.co.in",
    "indianrail.gov.in", "parivahan.gov.in", "indiapost.gov.in", "incometax.gov.in", "gst.gov.in",
    "uidai.gov.in", "digilocker.gov.in", "umang.gov.in", "mygov.in", "india.gov.in", "nic.in",
    "cert-in.org.in", "cybercrime.gov.in", "epfindia.gov.in", "passportindia.gov.in", "ugc.ac.in",
    "aicte-india.org", "nielit.gov.in", "manipal.edu", "onlinemanipal.com", "iitb.ac.in",
    "iitd.ac.in", "iitm.ac.in", "iitk.ac.in", "bhu.ac.in", "du.ac.in", "flipkart.com",
    "myntra.com", "ajio.com", "nykaa.com", "meesho.com", "zomato.com", "swiggy.com",
    "bigbasket.com", "blinkit.com", "zeptonow.com", "olacabs.com", "uber.com", "makemytrip.com",
    "goibibo.com", "cleartrip.com", "yatra.com", "redbus.in", "bookmyshow.com", "jio.com",
    "airtel.in", "myvi.in", "bsnl.co.in", "tcs.com", "infosys.com", "wipro.com", "hcltech.com",
    "techmahindra.com", "zoho.com", "freshworks.com", "postman.com", "browserstack.com",
    "thehindu.com", "indianexpress.com", "ndtv.com", "hindustantimes.com", "timesofindia.indiatimes.com"
}


def is_whitelisted_domain(domain: str, url: str) -> bool:
    parsed = urlsplit(url)
    return (
        (domain in GLOBAL_TRUSTED_DOMAINS or domain in INDIAN_TRUSTED_DOMAINS)
        and parsed.scheme == "https"
        and parsed.netloc.lower() == domain
        and parsed.path in ("", "/")
        and not parsed.query
        and not parsed.fragment
    )
