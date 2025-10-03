""" Data identifier class implementation """

class Identifier:
    """Data identifier class containing all methods to identify sensitive data in files

    Configurable Variables:
        regexes (array-dict): an array list of dictionaries for identifying different type of data.
            pattern (str): regular expression to identify
            type (tuple): description of options for type of data.
    """
    regexes = [
        {
            "pattern": r"\S*@\S*",
            "type": ("at_symbol", "contains_at")
        },
        {
            "pattern": r"([a-z0-9!#$%&'*+\/=?^_`{|.}~-]+@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)",
            "type": ("emails", "email")
        },
        {
            "pattern": r'(?i)((?:https?://|www\d{0,3}[.])?[a-z0-9.\-]+[.](?:(?:international)|(?:construction)|(?:contractors)|(?:enterprises)|(?:photography)|(?:immobilien)|(?:management)|(?:technology)|(?:directory)|(?:education)|(?:equipment)|(?:institute)|(?:marketing)|(?:solutions)|(?:builders)|(?:clothing)|(?:computer)|(?:democrat)|(?:diamonds)|(?:graphics)|(?:holdings)|(?:lighting)|(?:plumbing)|(?:training)|(?:ventures)|(?:academy)|(?:careers)|(?:company)|(?:domains)|(?:florist)|(?:gallery)|(?:guitars)|(?:holiday)|(?:kitchen)|(?:recipes)|(?:shiksha)|(?:singles)|(?:support)|(?:systems)|(?:agency)|(?:berlin)|(?:camera)|(?:center)|(?:coffee)|(?:estate)|(?:kaufen)|(?:luxury)|(?:monash)|(?:museum)|(?:photos)|(?:repair)|(?:social)|(?:tattoo)|(?:travel)|(?:viajes)|(?:voyage)|(?:build)|(?:cheap)|(?:codes)|(?:dance)|(?:email)|(?:glass)|(?:house)|(?:ninja)|(?:photo)|(?:shoes)|(?:solar)|(?:today)|(?:aero)|(?:arpa)|(?:asia)|(?:bike)|(?:buzz)|(?:camp)|(?:club)|(?:coop)|(?:farm)|(?:gift)|(?:guru)|(?:info)|(?:jobs)|(?:kiwi)|(?:land)|(?:limo)|(?:link)|(?:menu)|(?:mobi)|(?:moda)|(?:name)|(?:pics)|(?:pink)|(?:post)|(?:rich)|(?:ruhr)|(?:sexy)|(?:tips)|(?:wang)|(?:wien)|(?:zone)|(?:biz)|(?:cab)|(?:cat)|(?:ceo)|(?:com)|(?:edu)|(?:gov)|(?:int)|(?:mil)|(?:net)|(?:onl)|(?:org)|(?:pro)|(?:red)|(?:tel)|(?:uno)|(?:xxx)|(?:ac)|(?:ad)|(?:ae)|(?:af)|(?:ag)|(?:ai)|(?:al)|(?:am)|(?:an)|(?:ao)|(?:aq)|(?:ar)|(?:as)|(?:at)|(?:au)|(?:aw)|(?:ax)|(?:az)|(?:ba)|(?:bb)|(?:bd)|(?:be)|(?:bf)|(?:bg)|(?:bh)|(?:bi)|(?:bj)|(?:bm)|(?:bn)|(?:bo)|(?:br)|(?:bs)|(?:bt)|(?:bv)|(?:bw)|(?:by)|(?:bz)|(?:ca)|(?:cc)|(?:cd)|(?:cf)|(?:cg)|(?:ch)|(?:ci)|(?:ck)|(?:cl)|(?:cm)|(?:cn)|(?:co)|(?:cr)|(?:cu)|(?:cv)|(?:cw)|(?:cx)|(?:cy)|(?:cz)|(?:de)|(?:dj)|(?:dk)|(?:dm)|(?:do)|(?:dz)|(?:ec)|(?:ee)|(?:eg)|(?:er)|(?:es)|(?:et)|(?:eu)|(?:fi)|(?:fj)|(?:fk)|(?:fm)|(?:fo)|(?:fr)|(?:ga)|(?:gb)|(?:gd)|(?:ge)|(?:gf)|(?:gg)|(?:gh)|(?:gi)|(?:gl)|(?:gm)|(?:gn)|(?:gp)|(?:gq)|(?:gr)|(?:gs)|(?:gt)|(?:gu)|(?:gw)|(?:gy)|(?:hk)|(?:hm)|(?:hn)|(?:hr)|(?:ht)|(?:hu)|(?:id)|(?:ie)|(?:il)|(?:im)|(?:in)|(?:io)|(?:iq)|(?:ir)|(?:is)|(?:it)|(?:je)|(?:jm)|(?:jo)|(?:jp)|(?:ke)|(?:kg)|(?:kh)|(?:ki)|(?:km)|(?:kn)|(?:kp)|(?:kr)|(?:kw)|(?:ky)|(?:kz)|(?:la)|(?:lb)|(?:lc)|(?:li)|(?:lk)|(?:lr)|(?:ls)|(?:lt)|(?:lu)|(?:lv)|(?:ly)|(?:ma)|(?:mc)|(?:md)|(?:me)|(?:mg)|(?:mh)|(?:mk)|(?:ml)|(?:mm)|(?:mn)|(?:mo)|(?:mp)|(?:mq)|(?:mr)|(?:ms)|(?:mt)|(?:mu)|(?:mv)|(?:mw)|(?:mx)|(?:my)|(?:mz)|(?:na)|(?:nc)|(?:ne)|(?:nf)|(?:ng)|(?:ni)|(?:nl)|(?:no)|(?:np)|(?:nr)|(?:nu)|(?:nz)|(?:om)|(?:pa)|(?:pe)|(?:pf)|(?:pg)|(?:ph)|(?:pk)|(?:pl)|(?:pm)|(?:pn)|(?:pr)|(?:ps)|(?:pt)|(?:pw)|(?:py)|(?:qa)|(?:re)|(?:ro)|(?:rs)|(?:ru)|(?:rw)|(?:sa)|(?:sb)|(?:sc)|(?:sd)|(?:se)|(?:sg)|(?:sh)|(?:si)|(?:sj)|(?:sk)|(?:sl)|(?:sm)|(?:sn)|(?:so)|(?:sr)|(?:st)|(?:su)|(?:sv)|(?:sx)|(?:sy)|(?:sz)|(?:tc)|(?:td)|(?:tf)|(?:tg)|(?:th)|(?:tj)|(?:tk)|(?:tl)|(?:tm)|(?:tn)|(?:to)|(?:tp)|(?:tr)|(?:tt)|(?:tv)|(?:tw)|(?:tz)|(?:ua)|(?:ug)|(?:uk)|(?:us)|(?:uy)|(?:uz)|(?:va)|(?:vc)|(?:ve)|(?:vg)|(?:vi)|(?:vn)|(?:vu)|(?:wf)|(?:ws)|(?:ye)|(?:yt)|(?:za)|(?:zm)|(?:zw))(?:/[^\s()<>]+[^\s`!()\[\]{};:\'".,<>?\xab\xbb\u201c\u201d\u2018\u2019])?)',
            "type": ("dns", "domain")
        },
        {
            "pattern": r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
            "type": ("ip", "ipv4")
        },
        {
            "pattern": '((?:(?:\\d{4}[- ]?){3}\\d{4}|\\d{15,16}))(?![\\d])',
            "type": ("cc", "creditcard")
        },
        {
            "pattern": r"[STFGM]\d{7}[A-Z]",
            "type": ("nric", "fin", "ic")
        },
        {
            "pattern": r'(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))',
            "type": ("ipv6", "ip6")
        },
        {
            "pattern": r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
            "type": ("base64", "b64")
        },
        {
            "pattern": r"\+91-\d{5}-\d{5}",  # Indian mobile numbers
            "type": ("phone", "mobile")
        },
        {
            "pattern": r"\+91-\d{2}-\d{4}-\d{4}",  # Indian home numbers
            "type": ("phone", "home")
        },
        {
            "pattern": r"\d{4} \d{4} \d{4}",  # Aadhaar
            "type": ("aadhaar",)
        },
        {
            "pattern": r"[A-Z]{5}\d{4}[A-Z]",  # PAN
            "type": ("pan",)
        },
        {
            "pattern": r"\bBN-\d{6}\b",  # Boarding pass sample
            "type": ("boarding_pass",)
        },

        # ✅ Newly added regexes from your test file:
        {
            "pattern": r"[A-Z]{2}\d{7}",  # Passport (e.g., XN1234567)
            "type": ("passport",)
        },
        {
            "pattern": r"[A-Z]{2}\d{2}-\d{4}-\d{7}",  # Driver's License (e.g., WB20-2025-9988776)
            "type": ("drivers_license",)
        },
        {
            "pattern": r"\d{9}",  # Bank Account Number (generic 9+ digits)
            "type": ("bank_account",)
        },
        {
            "pattern": r"[A-Z]{4}0\d{6}",  # IFSC code
            "type": ("ifsc",)
        },
        {
            "pattern": r"[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}",  # SWIFT/BIC
            "type": ("swift",)
        },
        {
            "pattern": r"(?:AIza[0-9A-Za-z-_]{35})",  # Google API Key
            "type": ("google_api",)
        },
        {
            "pattern": r"(?:sk_live|sk_test)_[0-9a-zA-Z]{24,}",  # Stripe key
            "type": ("stripe",)
        },
        {
            "pattern": r"AKIA[0-9A-Z]{16}",  # AWS Access Key
            "type": ("aws_access",)
        },
        {
            "pattern": r"wJalrXUtnFEMI/[0-9a-zA-Z+/]+",  # AWS Secret (simplified)
            "type": ("aws_secret",)
        },
        {
            "pattern": r"eyJ[a-zA-Z0-9._-]+",  # JWT Token
            "type": ("jwt",)
        },
        {
            "pattern": r"1//[0-9a-zA-Z\-_]+",  # OAuth Refresh Token
            "type": ("oauth_refresh",)
        },
        {
            "pattern": r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}",  # MAC address
            "type": ("mac",)
        },
        {
            "pattern": r"MRN-\d{8}",  # Medical Record Number
            "type": ("medical_record",)
        },
        {
            "pattern": r"SHI-POL-\d{4}-\d{6}",  # Insurance Policy
            "type": ("insurance_policy",)
        },
        {
            "pattern": r"WB\d{2}[A-Z]{2}\d{4}",  # License Plate
            "type": ("license_plate",)
        },
        {
            "pattern": r"RC-[A-Z]{2}-\d{4}-\d{6}",  # Vehicle RC
            "type": ("vehicle_rc",)
        },
        {
            "pattern": r"CAL-UNI-\d{4}-\d{4}",  # Student ID
            "type": ("student_id",)
        },
        {
            "pattern": r"LIB-\d{4}-[A-Z]{3}-\d{4}",  # Library Card
            "type": ("library_card",)
        }
    ]

    def __init__(self) -> None:
        return None
