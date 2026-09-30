/* Packet-sequence mutation shared by the two AFL custom mutators.
 * Data mutation edits packet bytes. Order mutation inserts, deletes,
 * reorders, or inserts a delivery-interval gap. A SUM or XOR token is recomputed. */
static int gvap_hex(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t gvap_fix_checksum(uint8_t *buf, size_t n)
{
    size_t i = 0, kind_at = 0;
    int kind = 0;
    unsigned sum = 0;
    static const char *hexd = "0123456789ABCDEF";
    while (i < n) {
        while (i < n && (buf[i] == ' ' || buf[i] == '\n' || buf[i] == '\t'))
            i++;
        if (i + 3 <= n && (buf[i + 3] == ' ' || buf[i + 3] == '\n' || buf[i + 3] == '\t' || i + 3 == n) &&
            ((!memcmp(buf + i, "SUM", 3) && (kind = 1)) || (!memcmp(buf + i, "XOR", 3) && (kind = 2)))) {
            kind_at = i;
            break;
        }
        kind = 0;
        while (i < n && buf[i] != ' ' && buf[i] != '\n' && buf[i] != '\t')
            i++;
    }
    if (!kind)
        return n;
    i = 0;
    while (i < kind_at) {
        int hi, lo;
        while (i < kind_at && (buf[i] == ' ' || buf[i] == '\n' || buf[i] == '\t'))
            i++;
        if (i >= kind_at)
            break;
        hi = gvap_hex(buf[i]);
        lo = (i + 1 < kind_at) ? gvap_hex(buf[i + 1]) : -1;
        if (hi >= 0 && lo >= 0) {
            unsigned v = ((unsigned)hi << 4) | (unsigned)lo;
            sum = (kind == 2) ? (sum ^ v) : ((sum + v) & 0xFFu);
        }
        while (i < kind_at && buf[i] != ' ' && buf[i] != '\n' && buf[i] != '\t')
            i++;
    }
    i = kind_at + 3;
    while (i < n && (buf[i] == ' ' || buf[i] == '\n' || buf[i] == '\t'))
        i++;
    if (i + 1 < n && gvap_hex(buf[i]) >= 0 && gvap_hex(buf[i + 1]) >= 0) {
        buf[i] = (uint8_t)hexd[(sum >> 4) & 0xF];
        buf[i + 1] = (uint8_t)hexd[sum & 0xF];
    }
    return n;
}

static size_t gvap_packet_fuzz(uint8_t *dst, size_t cap, const uint8_t *src, size_t n, unsigned seed)
{
    unsigned op;
    if (!cap)
        return 0;
    if (n >= cap)
        n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = 0;
    op = seed % 5u;
    if (op == 0 && n) {
        size_t at = seed % n, k;
        int flipped = 0;
        static const char *hexd = "0123456789ABCDEF";
        for (k = 0; k < n; k++) {
            size_t j = (at + k) % n;
            int h = gvap_hex((int)dst[j]);
            if (h < 0)
                continue;
            dst[j] = (uint8_t)hexd[(h + 1 + (int)(seed & 7)) & 0xF];
            flipped = 1;
            break;
        }
        if (!flipped)
            dst[at] ^= (uint8_t)(1u << ((seed >> 3) & 7));
    } else if (op == 1 && n + 1 < cap) {
        size_t at = n ? seed % (n + 1) : 0;
        memmove(dst + at + 1, dst + at, n - at);
        dst[at] = (uint8_t)(seed >> 8);
        n++;
    } else if (op == 2 && n > 1) {
        size_t at = seed % n;
        memmove(dst + at, dst + at + 1, n - at - 1);
        n--;
    } else if (op == 3 && n > 1) {
        uint8_t b = dst[0];
        memmove(dst, dst + 1, n - 1);
        dst[n - 1] = b;
    } else if (n + 1 < cap) {
        size_t at = n ? seed % (n + 1) : 0;
        memmove(dst + at + 1, dst + at, n - at);
        dst[at] = 0;
        n++;
    }
    return gvap_fix_checksum(dst, n);
}
