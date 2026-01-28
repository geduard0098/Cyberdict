
#!/usr/bin/env python3
"""
 CCC  Y   Y BBBB  EEEEE RRRR  DDDD  III  CCC  TTTTT 
C   C  Y Y  B   B E     R   R D   D  I  C   C   T   
C       Y   BBBB  EEEE  RRRR  D   D  I  C       T   
C   C   Y   B   B E     R  R  D   D  I  C   C   T   
 CCC    Y   BBBB  EEEEE R   R DDDD  III  CCC    T   
                                                    
Cyber Dictionary - Terminal UI (TUI) v0.2
------------------------------------
### Made with ChatGPT & Gemini ###

Features:
- Search for terms with a live autocomplete suggestion list (type-ahead).
- Press TAB to autocomplete to the currently selected suggestion.
- Navigate suggestions with Up/Down arrows and press Enter to view a term.
- Press 'l' (lowercase L) to view all terms in a scrollable list and select one.
- Press Ctrl-C or 'q' to quit.

Implementation notes:
- Data is stored in CYBER_DICT (a dictionary mapping term -> {definition, bonus}).
- Prefix search uses a bisect on a pre-sorted lowercase list for efficiency (O(log n) + k).
- The UI is implemented using the standard `curses` library (Unix-like terminals).
- No external dependencies required.

How to run:
    python3 cyberdict.py

(If running on Windows, install a curses compatibility package, e.g. `windows-curses`.)


"""

import curses
import textwrap
import bisect
import locale
import sys

locale.setlocale(locale.LC_ALL, '')  # respect terminal encoding

# ----------------------------
# 1) The dictionary data model
# ----------------------------
# Keys are canonical terms. Values are dicts with 'definition' and 'bonus' fields. Add or edit entries here.
CYBER_DICT = {
    "Phishing": {
        "definition": (
            "Phishing is a form of cybercrime where an attacker poses as a legitimate "
            "institution or person to lure individuals into providing sensitive data. "
            "This data usually includes personally identifiable information (PII), "
            "banking and credit card details, and passwords."
        ),
        "bonus": (
            ">>>1.The Core Mechanism: How It Works<<<\n\n"
            "------------------------------ \n\n"
            "Phishing attacks generally follow a four-phase lifecycle:\n\n"
            "1) Reconnaissance: The attacker identifies targets and gathers information "
            "(email addresses, organizational structure, recent purchases).\n\n"
            "2) Weaponization: The attacker creates a lure. This could be a fake login "
            "page for Microsoft 365, a malicious PDF invoice, or a spoofed email from a CEO.\n\n"
            "3) Delivery: The message is sent via email, SMS, social media, or voice call.\n\n"
            "4) Exploitation: The victim acts on the lure (clicks a link, downloads a file, "
            "or enters credentials), allowing the attacker to steal data or install malware.\n\n"
            "---------------------------------------------------------------------------------------------------------------------------------------------------------\n\n"
            ">>>2.Common Phishing Techniques<<<\n\n"
            "------------------------------ \n\n"
            "Spear Phishing: Highly targeted attacks aimed at specific individuals or organizations. "
            "The attacker customizes the message using personal details to increase credibility.\n\n"
            "Whaling: A type of spear phishing that targets high-profile individuals like CEOs or CFOs. "
            "The stakes are higher, as these individuals often have access to sensitive company data.\n\n"
            "Clone Phishing: The attacker creates a nearly identical copy of a legitimate email "
            "but replaces links or attachments with malicious ones. The email appears to come from a "
            "trusted source, making it more likely the victim will fall for it.\n\n"
            "Vishing (Voice Phishing): The attacker uses phone calls to impersonate a trusted entity, "
            "like a bank or government agency, to extract sensitive information.\n\n"   

        )
    },
    "Malware": {
        "definition": (
                    "Malware, short for malicious software, "
                    "is any code or program specifically designed to damage, disrupt, or gain "
                    "unauthorized access to a computer system, network, or device."
        ),
        "bonus": (
                    "Unlike a bug (which is an accidental mistake in code), malware is created with intent.\n\n"
                    ">>>1. Common Types of Malware<<<\n\n"
                    "------------------------------ \n\n"

                    "Malware is generally classified by how it spreads and what it does once it infects a system. "
                    "Here are the most common types of malware currently in circulation:\n\n"

                    "Viruses: Malicious code that attaches itself to a legitimate program (like an .exe or a Word doc). "
                    "It requires a human to run the file to activate and spread.\n\n"

                    "Worms: Unlike viruses, these are self-replicating and do not need a host file or human help. "
                    "They exploit network vulnerabilities to slither from one computer to another automatically.\n\n"

                    "Trojans: Named after the Greek myth, these disguise themselves as legitimate software (e.g., a free video player or a PDF update). "
                    "Once you install them, they release a hidden malicious payload.\n\n"
                    "---------------------------------------------------------------------------------------------------------------------------------------------------------\n\n"

                    ">>>2. High-Impact & Specialized Malware<<<\n\n"
                    "------------------------------ \n\n"
                    "These are defined by the specific damage they cause:\n\n"

                    "Ransomware: Encrypts your files or locks your system, demanding a payment (usually in cryptocurrency) for the decryption key."
                    " Modern versions often use \"double extortion,\" threatening to leak your private data if you don't pay.\n\n"

                    "Infostealers / Spyware: Designed to remain invisible while monitoring your activity."
                    "This includes Keyloggers (which record every keystroke to steal passwords) and tools that scrape your browser for saved credit cards and cookies.\n\n"

                    "Rootkits: Deep-level malware that infects the Operating System itself. "
                    "They are incredibly hard to detect because they can hide their own existence from traditional antivirus software.\n\n"

                    "Cryptojackers: This malware \"hijacks\" your CPU and GPU power to mine cryptocurrency for the attacker. "
                    "You might notice your computer running hot, loud, or very slowly for no apparent reason.\n\n"

        )
    },
    "Botnet": {
        "definition": ( 
                    "A botnet (a portmanteau of \"robot\" and \"network\") "
                    "is a collection of internet-connected devices—such as PCs, smartphones, and smart home (IoT) gadgets—"
                    "that have been infected with malware and are controlled as a group by a single attacking party."
        ),
        "bonus": (
            ">>>1. How a Botnet is Built<<<\n\n"
            "------------------------------ \n\n"

            "The creation of a botnet generally follows a three-step lifecycle:\n\n"

            "Infection (Recruitment): The attacker spreads malware through phishing emails, unpatched software vulnerabilities, or \"drive-by\" downloads." 
            "When a user unknowingly downloads and executes the malware, their device becomes part of the botnet.\n\n"

            "Connection: Once infected, the device \"phones home\" to a Command and Control (C2) server."
            "This establishes a communication channel so the bot-herder can send instructions.\n\n"

            "Mobilization: Once the attacker has enough \"bots\" (ranging from a few hundred to millions), they can execute a coordinated attack\n\n"
            "---------------------------------------------------------------------------------------------------------------------------------------------------------\n\n"

            ">>>2. What are Botnets Used For?<<<\n\n"
            "------------------------------ \n\n"

            "A botnet’s power comes from scale. While one computer can't do much, 100,000 computers acting together can be devastating:\n\n"

            "DDoS Attacks: Flooding a website with so much traffic from so many different sources that it crashes.\n\n"

            "Spam & Phishing: Sending millions of emails simultaneously. Using a botnet makes the spam look like it's coming from \"real\" people, helping it bypass filters.\n\n"

            "Cryptojacking: Using the combined processing power of the entire network to mine cryptocurrency for the attacker.\n\n"

            "Credential Stuffing: Trying millions of stolen usernames and passwords on a login page at once to break into accounts."
        )
    },
    "DDoS": {
        "definition": (
            "In simple terms, a Distributed Denial of Service (DDoS) attack is like a massive, "
            "coordinated crowd suddenly rushing a small shop at once. The shop isn't being robbed; "
            "it’s just so packed that legitimate customers can't get through the door, "
            "and the staff is too overwhelmed to do anything but crash.\n\n" 
             
            "Technically, it is a malicious attempt to disrupt the normal traffic of a targeted server, service, "
            "or network by overwhelming the target or its surrounding infrastructure with a flood of Internet traffic."
            ),
        
        "bonus": (
            ">>>1.How a DDoS Attack Works<<<\n\n"
            "------------------------------ \n\n"
            "The effectiveness of a DDoS attack comes from the use of multiple compromised computer systems as sources of attack traffic.\n\n"

            "Building the Botnet: An attacker gains control of a network of online machines (computers, smartphones, or IoT devices like smart cameras)"
            "by infecting them with malware. Each of these devices is called a \"bot\" or \"zombie.\"\n\n"

            "The Command: The attacker organizes these bots into a group called a botnet.\n\n"

            "The Assault: Once the botnet is established, the attacker can direct the machines by sending remote instructions to each bot. "
            "When a victim’s IP address is targeted, each bot responds by sending a stream of requests to the target, causing the server or network to reach capacity.\n\n"
            "---------------------------------------------------------------------------------------------------------------------------------------------------------\n\n"
            ">>>2.How to Mitigate an Attack\n\n"
            "------------------------------ \n\n"

            "Defending against a DDoS attack is tricky because it’s hard to tell the difference between \"bad\" traffic and a sudden spike in \"good\" traffic (like a viral news story).\n\n"

            "Black Hole Routing: Routing all traffic into a \"black hole\" (null route) and dropping it." 
            "This stops the server from crashing but also takes the site offline for everyone.\n\n"

            "Rate Limiting: Limiting the number of requests a server will accept over a certain time window.\n\n"

            "Web Application Firewall (WAF): A tool that helps filter traffic based on specific rules to identify and block Layer 7 attacks.\n\n"

            "Anycast Network Diffusion: Using a large network of servers to \"scatter\" the attack traffic across many different points, absorbing the impact so no single server goes down"
            )
    },
    "Social Engineering": {
        "definition": (
            "In the world of cybersecurity, Social Engineering is the art of manipulating people into giving up confidential information.\n\n"
            "While hackers often try to find a \"bug\" in a computer’s code, social engineers look for a \"bug\" in human psychology.\n\n"

            "It’s much easier to trick someone into giving away their password than it is to try and crack that password through brute force."
            ),
        "bonus": (
            ">>>1.The Social Engineering Lifecycle<<<\n\n"
            "------------------------------ \n\n"
            "Social engineering isn't always a quick \"one-off\" interaction. Professional attackers often follow a four-step cycle to ensure success:\n\n"

            "Investigation: Identifying the victim and gathering background information (e.g., where they work, who their friends are, or what services they use).\n\n"

            "Hook: Engaging the victim, often by creating a sense of urgency or trust to start the \"story.\"\n\n"

            "Play: Executing the actual attack to gain information or access over time.\n\n"

            "Exit: Closing the interaction without raising suspicion, ideally by removing traces of the malware or interaction.\n\n"
            "---------------------------------------------------------------------------------------------------------------------------------------------------------\n\n"

            ">>>2.How to Protect Yourself\n\n"
            "------------------------------ \n\n"
            "The best defense against social engineering isn't a better antivirus; it's skepticism.\n\n"

            "Slow Down: Attackers want you to act fast. If a message feels urgent, take a breath and verify the source.\n\n"

            "Verify the Sender: Check the \"From\" email address carefully for typos (e.g., support@micros0ft.com instead of microsoft.com).\n\n"

            "Don't Click, Type: Instead of clicking a link in an email, go directly to the official website by typing the URL into your browser.\n\n"   

            "Enable MFA: Multi-Factor Authentication (MFA) is your best safety net. Even if a hacker gets your password, they still can't get in without that second code.\n\n"

            )
    },
    "Zero-day": {
        "definition": (
            "A Zero-Day Vulnerability is a software security flaw that is known to the software vendor or developer exactly zero days before an attack occurs.\n\n"

            "In the world of cybersecurity, this is the \"holy grail\" for hackers. "
            "Because the creators of the software don't know the hole exists, there is no \"patch\" (fix) available to block the exploit. "
            "It’s like discovering a secret back door into a bank that the architect didn't know they built."

            ),
        "bonus": (
            ">>>1.The Zero-Day Timeline<<<\n\n"
            "------------------------------ \n\n"
            "The term \"Zero-Day\" actually refers to several different stages of the flaw's life. Understanding the timeline is key to seeing why they are so dangerous:\n\n"

            "Vulnerability Created: A programmer accidentally writes a bug into the code. It sits there, undiscovered.\n\n"

            "Vulnerability Discovered: A hacker (or a security researcher) finds the bug. If a hacker finds it first, they keep it secret to use for attacks.\n\n"

            "Exploit Developed: The attacker writes a piece of code (the Zero-Day Exploit) specifically designed to use that bug to break into systems.\n\n"

            "The Attack: The exploit is released. This is the \"Zero Day\"—the moment the world realizes there is a hole.\n\n"

            "The Fix: The software company rushes to create a patch. Once the patch is released, it is no longer a \"Zero-Day\" vulnerability; it's just a regular security flaw.\n\n"
            "---------------------------------------------------------------------------------------------------------------------------------------------------------\n\n"

            ">>>2.How do you defend against something unknown?<<<\n\n"
            "------------------------------ \n\n"
            "You can't patch what you don't know about, so defense relies on layered security and behavioral analysis:\n\n"

            "Heuristic Analysis: Modern security tools don't just look for \"known\" viruses; they look for suspicious behavior. "
            "If a simple Word document suddenly tries to change system files, the security software blocks it, even if it doesn't recognize the specific virus.\n\n"

            "Sandboxing: Running suspicious programs in a \"sandbox\" (a virtual isolated environment) to see what they do before letting them touch the rest of the computer.\n\n"

            "Bug Bounties: Many companies (like Google and Apple) pay hackers thousands of dollars to report vulnerabilities to them instead of selling them to criminals.\n\n"

            "Zero Trust Architecture: Assuming the network is already compromised and requiring strict verification for every single person and device trying to access resources."
            )
    },
    "Encryption": {
        "definition": (
            "Encryption is the process of scrambling plain, readable information into a format that looks like gibberish to anyone who doesn't have the secret \"key\" to unlock it.\n\n"

            "It is the primary way we ensure confidentiality in a world where data is constantly being intercepted or stolen. "
            "If a hacker steals an encrypted file, they haven’t stolen a secret—they’ve just stolen a puzzle they can't solve."
            
            ),
        "bonus": (
            ">>>1.The Core Components<<<\n\n"
            "------------------------------ \n\n"

            "To understand encryption, you need to know these four basic terms:\n\n"

            "Plaintext: The original, readable message (e.g., \"Hello, Bob\").\n\n"

            "Ciphertext: The scrambled, unreadable version of that message (e.g., \"Gdkkn, Anm\").\n\n"

            "Algorithm (Cipher): The mathematical formula or \"rule\" used to scramble the data.\n\n"

            "Key: A unique string of bits (like a password) used by the algorithm to lock or unlock the data.\n\n"
            "---------------------------------------------------------------------------------------------------------------------------------------------------------\n\n"

            ">>>2. Two Main Types of Encryption<<<\n\n"
            "------------------------------ \n\n"

            "There are two ways to handle the \"keys\" used in encryption. Both are essential for modern internet security.\n\n"

            "1. Symmetric Encryption (Secret Key)\n\n"
            "In this method, the same key is used to both encrypt and decrypt the data. "
            "It's like a physical safe: you use one key to lock it, and you must give that exact same key to the person who needs to open it.\n\n"

            "Pro: It is incredibly fast and efficient for large amounts of data.\n\n"

            "Con: You have to find a secure way to share the key. If a hacker intercepts the key while you're sending it to a friend, they can read everything.\n\n"

            "Common Example: AES (Advanced Encryption Standard), used to protect the data on your hard drive.\n\n"
            "----------------------------------------------------------------------------------------------------------------------------------------------------------\n\n"

            "2. Asymmetric Encryption (Public Key)<<<"
         
            "This uses a pair of keys: a Public Key (which everyone can see) and a Private Key (which only you have).\n\n"

            "How it works: If someone wants to send you a secret, they lock it with your Public Key. "
            "Once it's locked, only your Private Key can open it. Even the person who locked it can't unlock it anymore.\n\n"

            "Pro: You never have to share your private secret key.\n\n"

            "Con: It is mathematically \"heavy\" and slower than symmetric encryption.\n\n"

            "Common Example: RSA or ECC, used to establish secure connections for websites (HTTPS)."
            )
    },
    "Firewall": {
        "definition": (
            "Think of a firewall as the digital equivalent of a security guard stationed at the entrance of a gated community. "
            "Its primary job is to inspect everyone trying to enter or leave,"
            "checking their credentials against a specific set of rules to decide who gets through and who gets turned away.\n\n"
            "In technical terms, a firewall is a network security device that monitors incoming and outgoing network traffic "
            "and decides whether to allow or block specific traffic based on a defined set of security rules."
            ),
        "bonus": (
            
            ">>>1.How a Firewall Works<<<\n\n"
            "------------------------------ \n\n"
            "A firewall sits at the junction between two networks—usually your private internal network (like your home Wi-Fi) and the public internet.\n\n"

            "It analyzes data packets, which are the small units of data used to transmit information over the internet. Each packet contains \"headers\" that tell the firewall:\n\n"

            "Where it’s coming from (Source IP address)\n\n"
            "Where it’s trying to go (Destination IP address)\n\n"
            "What service it wants to use (Port number, like port 80 for web browsing)\n\n"
            "If the packet matches the \"Allow\" list, it passes. If it looks suspicious or violates a rule, the firewall drops it.\n\n"
            "---------------------------------------------------------------------------------------------------------------------------------------------------------\n\n"
            
            ">>>2.Types of Firewalls<<<\n\n"
            "------------------------------ \n\n"
            "There are several types of firewalls, each with its own strengths and weaknesses:\n\n"
            "Packet-Filtering Firewalls: The most basic type, which checks packets against a set of rules. "
            "It’s fast but can be fooled by more sophisticated attacks.\n\n"
            "Stateful Inspection Firewalls: These keep track of the state of active connections and make decisions based on the context of the traffic. "
            "They are more secure than simple packet filters.\n\n"
            "Proxy Firewalls: These act as intermediaries between your network and the internet. "
            "They can inspect the entire data packet and provide additional security features like content filtering.\n\n"
            "Next-Generation Firewalls (NGFW): These combine traditional firewall capabilities with additional features like intrusion prevention, deep packet inspection, and application awareness."


        )
    },
    "Steganography": {
        "definition": (
            "Think of steganography as the art of hiding a message in plain sight."
            "While cryptography focuses on making a message unreadable to unauthorized eyes, "
            "steganography focuses on making sure no one even knows a message exists in the first place."
            ),
        "bonus": (
            ">>>1.How Steganography Works<<<\n\n"
            "------------------------------ \n\n"
            "At its core, steganography requires two elements: the cover object (the innocent file) and the secret data (the payload). "
             "By subtly altering the bits of the cover object, the secret data is embedded in a way that is statistically or visually imperceptible to humans.\n\n"

                "----------------------------------------------------------------------------------------------------------------------------------------------------------\n\n"

                ">>>2.Types of Steganography<<<\n\n"
                "------------------------------ \n\n"
                "Steganography isn't limited to just \"spy photos.\" It can be applied to almost any digital medium:\n\n"
                "Image Steganography: The most common form, where secret data is hidden within image files by modifying the least significant bits (LSBs) of pixel values.\n\n"
                "Audio Steganography: Hiding data within audio files by altering frequencies or embedding data in silent segments.\n\n"
                "Video Steganography: Combining image and audio techniques to hide data within video files.\n\n"
        )


    },
    "CIA Triad": {
        "definition": (
            "The CIA Triad is the foundational model used to guide information security policies within an organization. "
            "It's often pictured as a triangle because if any one of the three corners is compromised, the entire security posture collapses"
            
            ),

        "bonus": (
            ">>>1.The Three Pillars of the CIA Triad<<<\n\n"
            "------------------------------ \n\n"
            "Confidentiality: Ensuring that sensitive information is accessed only by authorized individuals. "
            "Techniques to maintain confidentiality include encryption, access controls, and authentication mechanisms.\n\n"
            "Integrity: Ensuring that data remains accurate and unaltered during storage or transmission. "
            "Methods to uphold integrity include hashing, checksums, and digital signatures.\n\n"
            "Availability: Ensuring that information and resources are accessible to authorized users when needed. "
            "Strategies to guarantee availability include redundancy, failover systems, and regular maintenance.\n\n"
            "---------------------------------------------------------------------------------------------------------------------------------------------------------\n\n"

            ">>>2.The Balancing Act<<<\n\n"
            "------------------------------ \n\n"
            "In the real world, you often have to trade off one for the other. For example:\n\n"
            "High Confidentiality (like 20-character passwords and 3-factor authentication) can hurt "
            "Availability because it makes it harder and slower for employees to get their work done.\n\n"
            "High Availability (allowing everyone to access a public folder quickly) might compromise Confidentiality.\n\n"

            "-----------------------------------------------------------------------------------------------------------------------------------------------------------\n\n"

            "Example Scenario: Online Banking\n\n"
            "Confidentiality: Only you (and authorized bank staff) can see your balance.\n\n"
            "Integrity: When you transfer $50, the system ensures exactly $50 is moved—not $500.\n\n"
            "Availability: You can log in to your banking app at 3:00 AM on a Sunday to check your transactions.\n\n"
            )
                  
    },
}

# ----------------------------
# 2) Efficient search helpers
# ----------------------------
# We'll build a sorted list of terms (case-insensitive) and parallel structures
# so prefix search is quick (bisect). This scales well to large dictionaries.

# TERMS:
#   - A sorted list of all dictionary terms (keys from CYBER_DICT).
#   - Sorting is done using s.lower() so the order is alphabetical
#     regardless of original capitalization (e.g. "DDoS" vs "Phishing").
#   - We keep the original casing so terms can be displayed nicely to the user.
#
# LOWER_TERMS:
#   - A parallel list containing the lowercase version of each term in TERMS.
#   - This allows efficient case-insensitive prefix searching using binary search
#     (bisect) without repeatedly calling lower() during every search.
#   - TERMS[i] and LOWER_TERMS[i] always refer to the same term.
TERMS = sorted(CYBER_DICT.keys(), key=lambda s: s.lower()) 
LOWER_TERMS = [t.lower() for t in TERMS] 

def prefix_matches(prefix: str, limit: int = 10):
    """
    Return up to `limit` terms whose lowercase form starts with `prefix` (case-insensitive).
    Uses bisect to find the start index in O(log n) time, then scans forward.

# Logic overview:
# 1) If the user has not typed anything yet (empty prefix),
#    return the first `limit` terms as default suggestions.
#
# 2) Convert the prefix to lowercase so matching is case-insensitive.
#
# 3) Use binary search (bisect_left) on the pre-sorted LOWER_TERMS list
#    to find the index where this prefix would appear alphabetically.
#    This avoids scanning the entire list and gives O(log n) performance.
#
# 4) Starting from that index, iterate forward while:
#    - We are still within bounds of the list
#    - The current term starts with the prefix
#    - We have not exceeded the requested result limit
#
# 5) For each match, append the correctly cased term from TERMS
#    (same index as LOWER_TERMS) to preserve display formatting.
#
# 6) Return the collected matches as autocomplete suggestions.
    """
    if not prefix:
        # if empty prefix, return the first `limit` terms
        return TERMS[:limit]
    p = prefix.lower()
    # compute left bound
    i = bisect.bisect_left(LOWER_TERMS, p)
    matches = []
    n = len(LOWER_TERMS)
    while i < n and LOWER_TERMS[i].startswith(p) and len(matches) < limit:
        matches.append(TERMS[i])
        i += 1
    return matches

# ----------------------------
# 3) Curses-based TUI
# ----------------------------

def draw_centered_text(win, y, text, attr=0):
    """Helper to draw text centered on the given y row."""
    maxy, maxx = win.getmaxyx()
    x = max((maxx - len(text)) // 2, 0)
    try:
        win.addstr(y, x, text[:maxx-1], attr)
    except curses.error:
        pass  # ignore when drawing outside bounds during resize

def wrap_text_for_width(text, width):
    """Wrap text to a given width (preserves paragraphs)."""
    paragraphs = text.split("\n\n")
    wrapped = []
    for p in paragraphs:
        lines = textwrap.wrap(p, width=width)
        if not lines:
            wrapped.append("")  # keep blank line
        else:
            wrapped.extend(lines)
        wrapped.append("")  # paragraph break
    if wrapped and wrapped[-1] == "":
        wrapped.pop()  # remove trailing extra blank
    return wrapped

def show_term_detail(stdscr, term):
    
    """Display definition and bonus info for `term` in a scrollable view."""

    # ---- layout constants ----
    LEFT_MARGIN = 2
    RIGHT_PADDING = 2
    LINE_GAP = 1

    # ---- styles ----
    STYLE_TITLE = curses.A_BOLD | curses.A_UNDERLINE
    STYLE_HEADER = curses.A_BOLD
    STYLE_BODY = curses.A_NORMAL
    STYLE_FOOTER = curses.A_DIM

    stdscr.clear()
    maxy, maxx = stdscr.getmaxyx()

    title = term
    definition = CYBER_DICT[term]["definition"]
    bonus = CYBER_DICT[term]["bonus"]

    text_width = maxx - LEFT_MARGIN - RIGHT_PADDING

    # ---- build structured content ----
    lines = []

    # Title
    lines.append(("title", title))
    lines.append(("rule", "-" * len(title)))
    lines.append(("spacer", ""))

    # Definition section
    lines.append(("header", ">>>Definition<<<"))
    lines.append(("spacer", ""))
    for line in wrap_text_for_width(definition, text_width):
        lines.append(("body", line))
    lines.append(("spacer", ""))

    # Bonus section
    lines.append(("header", ">>>Bonus Information<<<"))
    lines.append(("spacer", ""))
    for line in wrap_text_for_width(bonus, text_width):
        lines.append(("body", line))

    # ---- scrollable viewer ----
    top = 0
    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        view_height = h - 3  # leave space for footer

        for idx in range(view_height):
            line_idx = top + idx
            if line_idx >= len(lines):
                break

            line_type, text = lines[line_idx]

            try:
                if line_type == "title":
                    stdscr.addstr(idx, LEFT_MARGIN, text, STYLE_TITLE)
                elif line_type == "rule":
                    stdscr.addstr(idx, LEFT_MARGIN, text, STYLE_FOOTER)
                elif line_type == "header":
                    stdscr.addstr(idx, LEFT_MARGIN, text, STYLE_HEADER)
                else:  # body / spacer
                    stdscr.addstr(idx, LEFT_MARGIN, text, STYLE_BODY)
            except curses.error:
                pass

        # ---- footer ----
        stdscr.hline(h - 2, 0, curses.ACS_HLINE, w)
        footer = "↑↓ Scroll   |   b Back   |   q Quit"
        stdscr.addstr(h - 1, LEFT_MARGIN, footer, STYLE_FOOTER)

        stdscr.refresh()
        c = stdscr.getch()

        if c in (ord('b'), ord('B'), 27):
            return
        elif c == curses.KEY_UP and top > 0:
            top -= 1
        elif c == curses.KEY_DOWN and top + view_height < len(lines):
            top += 1
        elif c in (ord('q'), ord('Q')):
            sys.exit(0)

def list_all_terms(stdscr):
    """Show a scrollable list of all terms and allow selecting one to view details."""

    # ---- layout constants ----
    LEFT_MARGIN = 2
    RIGHT_PADDING = 2
    LIST_TOP = 3

    # ---- styles ----
    STYLE_TITLE = curses.A_BOLD
    STYLE_SELECTED = curses.A_REVERSE | curses.A_BOLD
    STYLE_NORMAL = curses.A_NORMAL
    STYLE_FOOTER = curses.A_DIM

    terms = TERMS
    top = 0
    selected = 0

    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        page_size = h - LIST_TOP - 3  # space for title + footer

        # ---- title ----
        title = "All Terms"
        subtitle = "Enter: view   ↑↓: navigate   b: back   q: quit"

        draw_centered_text(stdscr, 0, title, STYLE_TITLE)
        draw_centered_text(stdscr, 1, subtitle, STYLE_FOOTER)
        stdscr.hline(2, 0, curses.ACS_HLINE, w)

        # ---- list ----
        for i in range(page_size):
            idx = top + i
            if idx >= len(terms):
                break

            term = terms[idx]
            y = LIST_TOP + i
            attr = STYLE_SELECTED if idx == selected else STYLE_NORMAL

            try:
                stdscr.addstr(y, LEFT_MARGIN, term[: w - RIGHT_PADDING], attr)
            except curses.error:
                pass

        # ---- footer ----
        stdscr.hline(h - 2, 0, curses.ACS_HLINE, w)
        info = f"{selected + 1} / {len(terms)}"
        stdscr.addstr(h - 1, LEFT_MARGIN, info, STYLE_FOOTER)

        stdscr.refresh()
        c = stdscr.getch()

        if c == curses.KEY_UP:
            if selected > 0:
                selected -= 1
                if selected < top:
                    top = selected

        elif c == curses.KEY_DOWN:
            if selected < len(terms) - 1:
                selected += 1
                if selected >= top + page_size:
                    top = selected - page_size + 1

        elif c in (10, 13):  # Enter
            show_term_detail(stdscr, terms[selected])

        elif c in (ord('b'), ord('B'), 27):
            return

        elif c in (ord('q'), ord('Q')):
            sys.exit(0)

def search_mode(stdscr):
    """
    Interactive search mode with autocomplete.
    """

    # ---- layout constants ----
    LEFT_MARGIN = 2
    RIGHT_PADDING = 2
    SUGGESTIONS_TOP = 3
    MAX_SUGGESTIONS = 8

    # ---- styles ----
    STYLE_TITLE = curses.A_BOLD
    STYLE_HINT = curses.A_DIM
    STYLE_SELECTED = curses.A_REVERSE | curses.A_BOLD
    STYLE_NORMAL = curses.A_NORMAL

    curses.curs_set(1)
    stdscr.nodelay(False)
    stdscr.keypad(True)

    input_str = ""
    suggestion_index = 0

    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        text_width = w - LEFT_MARGIN - RIGHT_PADDING

        # ---- header ----
        draw_centered_text(stdscr, 0, "Search Cyber Dictionary", STYLE_TITLE)
        draw_centered_text(
            stdscr,
            1,
            "Type to search  |  TAB autocomplete  |  Enter view  |  l list  |  q quit",
            STYLE_HINT,
        )
        stdscr.hline(2, 0, curses.ACS_HLINE, w)

        # ---- suggestions ----
        suggestions = prefix_matches(input_str, limit=MAX_SUGGESTIONS)

        for i, term in enumerate(suggestions):
            y = SUGGESTIONS_TOP + i
            if y >= h - 4:
                break

            attr = STYLE_SELECTED if i == suggestion_index else STYLE_NORMAL
            marker = "→ " if i == suggestion_index else "  "

            try:
                stdscr.addstr(
                    y,
                    LEFT_MARGIN,
                    marker + term[:text_width - 2],
                    attr,
                )
            except curses.error:
                pass

        if not suggestions:
            stdscr.addstr(
                SUGGESTIONS_TOP,
                LEFT_MARGIN,
                "(no matches)",
                STYLE_HINT,
            )

        # ---- input field ----
        stdscr.hline(h - 4, 0, curses.ACS_HLINE, w)
        prompt = "Search: "
        stdscr.addstr(h - 3, LEFT_MARGIN, prompt, STYLE_TITLE)

        visible_input = input_str[-(text_width - len(prompt)) :]
        stdscr.addstr(
            h - 3,
            LEFT_MARGIN + len(prompt),
            visible_input,
            STYLE_NORMAL,
        )
        stdscr.move(
            h - 3,
            LEFT_MARGIN + len(prompt) + len(visible_input),
        )

        # ---- footer ----
        footer = "↑↓ Navigate   TAB Complete   Enter View   l List   q Quit"
        stdscr.addstr(h - 1, LEFT_MARGIN, footer, STYLE_HINT)

        stdscr.refresh()
        c = stdscr.get_wch()

        # ---- input handling ----
        if isinstance(c, str):
            if c == "\n":
                if suggestions:
                    term = suggestions[suggestion_index]
                    curses.curs_set(0)
                    show_term_detail(stdscr, term)
                    curses.curs_set(1)
                    input_str = ""
                    suggestion_index = 0
                else:
                    curses.beep()

            elif c == "\t":
                if suggestions:
                    input_str = suggestions[suggestion_index]
                    suggestion_index = 0
                else:
                    curses.beep()

            elif c in ("\x7f", "\b"):
                input_str = input_str[:-1]
                suggestion_index = 0

            elif c in ("\x03", "q", "Q"):
                raise KeyboardInterrupt

            elif c in ("l", "L"):
                curses.curs_set(0)
                list_all_terms(stdscr)
                curses.curs_set(1)
                input_str = ""
                suggestion_index = 0

            elif c.isprintable():
                input_str += c
                suggestion_index = 0

        else:
            if c == curses.KEY_UP and suggestion_index > 0:
                suggestion_index -= 1

            elif c == curses.KEY_DOWN and suggestion_index + 1 < len(suggestions):
                suggestion_index += 1

            elif c == curses.KEY_BACKSPACE:
                input_str = input_str[:-1]
                suggestion_index = 0

            elif c == 27:  # ESC
                return

def draw_ascii_art(win, start_y, art, attr=0):
    h, w = win.getmaxyx()
    for i, line in enumerate(art):
        if start_y + i >= h:
            break
        x = max((w - len(line)) // 2, 0)
        try:
            win.addstr(start_y + i, x, line[:w-1], attr)
        except curses.error:
            pass

def main(stdscr):

    ASCII_TITLE = [
    r"  ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ██╗ ██████╗████████╗",
    r" ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██║██╔════╝╚══██╔══╝",
    r" ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║  ██║██║██║        ██║   ",
    r" ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║  ██║██║██║        ██║   ",
    r" ╚██████╗   ██║   ██████╔╝███████╗██║  ██║██████╔╝██║╚██████╗   ██║   ",
    r"  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚═╝ ╚═════╝   ╚═╝   ",
    ]   

    # ---- curses setup ----
    curses.use_default_colors()
    stdscr.clear()
    stdscr.refresh()
    stdscr.keypad(True)
    curses.curs_set(0)

    # ---- styles ----
    

    STYLE_MENU = curses.A_NORMAL
    STYLE_PRIMARY = curses.A_BOLD
    STYLE_FOOTER = curses.A_DIM

    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()

        # ---- ASCII art ----
        draw_ascii_art(stdscr, 1, ASCII_TITLE, curses.A_BOLD)

       
        stdscr.hline(6, 0, curses.ACS_HLINE, w)

        # ---- menu ----
        menu_start = 8
        menu_items = [
            ("s", "Start search (type-ahead autocomplete)", True),
            ("l", "List all terms", False),
            ("q", "Quit", False),
        ]

        for i, (key, text, primary) in enumerate(menu_items):
            style = STYLE_PRIMARY if primary else STYLE_MENU
            line = f"[{key}] {text}"
            draw_centered_text(stdscr, menu_start + i * 2, line, style)

        # ---- footer ----
        stdscr.hline(h - 3, 0, curses.ACS_HLINE, w)
        draw_centered_text(
            stdscr,
            h - 2,
            "Press a key to continue",
            STYLE_FOOTER,
        )

        stdscr.refresh()

        try:
            c = stdscr.get_wch()
        except KeyboardInterrupt:
            return

        if isinstance(c, str):
            if c in ("s", "S", "\n"):
                try:
                    search_mode(stdscr)
                except KeyboardInterrupt:
                    return

            elif c in ("l", "L"):
                list_all_terms(stdscr)

            elif c in ("q", "Q"):
                return

            # ignore all other keys

        else:
            # treat Enter as search
            if c in (10, 13):
                try:
                    search_mode(stdscr)
                except KeyboardInterrupt:
                    return

# The `if __name__ == "__main__":` guard ensures that this code is executed
# only when the script is run directly, and not when it is imported as a module.
#
# `curses.wrapper(main)`:
#   - Initializes the terminal in curses mode (screen setup, input handling).
#   - Calls the `main(stdscr)` function with a properly configured screen object.
#   - Automatically restores the terminal to a normal state on exit,
#     even if an exception occurs.
#
# The try/except block:
#   - Catches KeyboardInterrupt (Ctrl-C) so the program can exit cleanly.
#   - Prevents the terminal from being left in a broken state.
#   - Prints a friendly exit message before terminating.
if __name__ == "__main__":
    try:
        curses.wrapper(main)
    except KeyboardInterrupt:
        # graceful exit on Ctrl-C
        print("\nExiting Cyber Dictionary. Goodbye!")
        sys.exit(0)

