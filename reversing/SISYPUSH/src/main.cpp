#define SDL_MAIN_HANDLED

#include <SDL.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstdio>

namespace {

constexpr int kScreenW = 960;
constexpr int kScreenH = 540;

constexpr float kWorldLeft = 0.0f;
constexpr float kWorldRight = 1800.0f;
constexpr float kSummitX = 1640.0f;
constexpr float kSummitMeters = 8848.0f;

constexpr uint32_t kTargetMeters = 8848;
constexpr uint32_t kTargetResets = 13;
constexpr uint32_t kFoundingDate = 20240710;

constexpr std::array<uint8_t, 8> kFoundingDigits = {2, 0, 2, 4, 0, 7, 1, 0};
constexpr std::array<uint32_t, kTargetResets> kRiteMeters = {
    710, 2024, 2407, 4071, 710, 2024, 2410, 7100, 2024, 407, 2407, 710, 8848,
};

struct Ball {
    float x = 70.0f;
    float vx = 0.0f;
    float radius = 18.0f;
    uint32_t scar = 0x53495359u ^ kFoundingDate;
    std::array<uint8_t, 16> core = {
        0x4d, 0x4a, 0x53, 0x45, 0x43, 0x20, 0x24, 0x07,
        0x10, 0x13, 0x37, 0x88, 0x48, 0x5a, 0x79, 0x70,
    };
};

struct GameState {
    Ball ball;
    uint32_t max_height_m = 0;
    uint32_t climb_peak_m = 0;
    uint32_t journey_digest = 0x243f6a88u;
    uint64_t live_digest = 0x6a09e667f3bcc909ull;
    uint64_t run_seed = 0;
    uint32_t checkpoint_m = 0;
    float checkpoint_x = 0.0f;
    uint32_t checkpoint_digest = 0x7102024u;
    uint32_t resets = 0;
    std::array<uint8_t, 29> tail_seal = {
        54, 3, 70, 241, 69, 230, 13, 186, 224, 116,
        135, 10, 6, 34, 246, 7, 135, 9, 24, 161,
        71, 17, 199, 90, 10, 91, 75, 120, 127,
    };
    bool head_revealed = false;
    bool full_revealed = false;
    bool checkpoint_seen = false;
};

float clampf(float v, float lo, float hi) {
    return std::max(lo, std::min(v, hi));
}

float smoothstep(float t) {
    t = clampf(t, 0.0f, 1.0f);
    return t * t * (3.0f - 2.0f * t);
}

float terrain_height_m(float x) {
    if (x < 120.0f) {
        return 0.0f;
    }
    if (x <= kSummitX) {
        const float t = (x - 120.0f) / (kSummitX - 120.0f);
        return kSummitMeters * smoothstep(t);
    }
    const float down = (x - kSummitX) / (kWorldRight - kSummitX);
    return kSummitMeters * (1.0f - 0.65f * smoothstep(down));
}

float terrain_slope_m_per_px(float x) {
    const float dx = 2.0f;
    return (terrain_height_m(x + dx) - terrain_height_m(x - dx)) / (2.0f * dx);
}

float terrain_x_at_meters(uint32_t meters) {
    float lo = 120.0f;
    float hi = kSummitX;
    const float target = clampf(static_cast<float>(meters), 0.0f, kSummitMeters);
    for (int i = 0; i < 28; ++i) {
        const float mid = (lo + hi) * 0.5f;
        if (terrain_height_m(mid) < target) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    return (lo + hi) * 0.5f;
}

int screen_x(float world_x) {
    const float t = (world_x - kWorldLeft) / (kWorldRight - kWorldLeft);
    return static_cast<int>(t * kScreenW);
}

int screen_y(float height_m) {
    const float t = height_m / kSummitMeters;
    return static_cast<int>(kScreenH - 54.0f - t * 420.0f);
}

uint32_t rotl32(uint32_t v, uint32_t r) {
    r &= 31u;
    return (v << r) | (v >> ((32u - r) & 31u));
}

uint8_t rotl8(uint8_t v, uint32_t r) {
    r &= 7u;
    return static_cast<uint8_t>((v << r) | (v >> ((8u - r) & 7u)));
}

uint8_t rotr8(uint8_t v, uint32_t r) {
    r &= 7u;
    return static_cast<uint8_t>((v >> r) | (v << ((8u - r) & 7u)));
}

uint8_t stream_byte(uint32_t state, uint32_t index, uint8_t lane) {
    state += (index + 1u) * 0x9e3779b1u + (static_cast<uint32_t>(lane) + 3u) * 0x85ebca6bu;
    state ^= state >> 15u;
    state *= 0x2c1b3c6du;
    state ^= state >> 12u;
    return static_cast<uint8_t>((state >> ((index & 3u) * 8u)) & 0xffu);
}

uint8_t unseal_byte(uint8_t c, uint32_t state, uint32_t index, uint8_t lane) {
    const uint8_t a = stream_byte(state, index, lane);
    const uint8_t b = stream_byte(state ^ 0xa5a5a5a5u, index + 7u, static_cast<uint8_t>(lane ^ 5u));
    uint8_t x = c;
    x = static_cast<uint8_t>(rotr8(x, (static_cast<uint32_t>(b >> 3u) + lane) & 7u) ^ static_cast<uint8_t>(a + b + index));
    x = static_cast<uint8_t>(x - b - 0x3du);
    x = rotr8(x, (static_cast<uint32_t>(a ^ index ^ lane) & 7u));
    x = static_cast<uint8_t>(x - a - index * 13u);
    return x;
}

uint32_t journey_step(uint32_t digest, uint32_t index, uint32_t mark) {
    digest ^= (mark * 0x7f4a7c15u) ^ ((index + 1u) * 0x045d9f3bu) ^ kFoundingDate;
    return rotl32(digest, kFoundingDigits[index & 7u] + index + 1u) + 0x9e3779b9u;
}

uint64_t mix64(uint64_t v) {
    v += 0x9e3779b97f4a7c15ull;
    v = (v ^ (v >> 30u)) * 0xbf58476d1ce4e5b9ull;
    v = (v ^ (v >> 27u)) * 0x94d049bb133111ebull;
    return v ^ (v >> 31u);
}

uint32_t checkpoint_noise(uint64_t seed, uint32_t index) {
    return static_cast<uint32_t>(mix64(seed ^ (static_cast<uint64_t>(index + 1u) * 0x9e3779b97f4a7c15ull)) >> 32u);
}

uint32_t checkpoint_height(uint64_t seed, uint32_t index) {
    const uint32_t upper = kRiteMeters[index];
    const uint32_t band = 180u + 70u * static_cast<uint32_t>(kFoundingDigits[index & 7u] + 1u);
    const uint32_t lower = (upper > band) ? (upper - band) : 1u;
    const uint32_t span = std::max(1u, upper - lower + 1u);
    return lower + (checkpoint_noise(seed, index) % span);
}

void choose_checkpoint(GameState& g) {
    if (g.resets >= kTargetResets) {
        g.checkpoint_m = kTargetMeters;
        g.checkpoint_x = kSummitX;
        g.checkpoint_seen = false;
        return;
    }

    g.checkpoint_m = checkpoint_height(g.run_seed, g.resets);
    g.checkpoint_x = terrain_x_at_meters(g.checkpoint_m);
    g.checkpoint_seen = false;
}

void initialize_run(GameState& g, uint64_t ticks) {
    const uint64_t timer = static_cast<uint64_t>(SDL_GetTicks64());
    g.run_seed = mix64(ticks ^ (timer << 17u) ^ static_cast<uint64_t>(kFoundingDate) ^ 0x5359534950555348ull);
    choose_checkpoint(g);
}

uint32_t roll_step(uint32_t state, uint32_t index, uint32_t lane) {
    return state * 1664525u + 1013904223u + (index + 1u) * 0x27d4eb2du + lane;
}

uint8_t checkpoint_tail_mask(const GameState& g, uint32_t index) {
    const uint32_t seed_low = static_cast<uint32_t>(g.run_seed);
    const uint32_t seed_high = static_cast<uint32_t>(g.run_seed >> 32u);
    const uint32_t state = g.checkpoint_digest
        ^ seed_low
        ^ rotl32(seed_high, (index + g.resets) & 31u)
        ^ ((index + 1u) * 0x7102024u)
        ^ (g.resets * 0x045d9f3bu);
    return static_cast<uint8_t>(
        stream_byte(state, index, static_cast<uint8_t>(0x71u + kFoundingDigits[index & 7u]))
        ^ stream_byte(state ^ 0xa5a5a5a5u, index + 13u, 0x0au));
}

void bind_tail_to_checkpoints(GameState& g) {
    for (size_t i = 0; i < g.tail_seal.size(); ++i) {
        g.tail_seal[i] = static_cast<uint8_t>(
            g.tail_seal[i] ^ checkpoint_tail_mask(g, static_cast<uint32_t>(i)));
    }
}

uint8_t tail_seal_byte(const GameState& g, uint32_t index) {
    uint8_t v = g.tail_seal[index];
    if (g.resets == kTargetResets) {
        v = static_cast<uint8_t>(v ^ checkpoint_tail_mask(g, index));
    }
    return v;
}

void turn_tail_seal(GameState& g, uint32_t index, uint32_t mark) {
    uint32_t roll = g.journey_digest ^ mark ^ 0xa341316cu ^ ((index + 1u) * 0x9e3779b1u);
    for (size_t i = 0; i < g.tail_seal.size(); ++i) {
        roll = roll_step(roll, index, static_cast<uint32_t>(i));
        const uint8_t mask = static_cast<uint8_t>(
            ((mark >> ((i & 3u) * 8u)) & 0xffu)
            ^ kFoundingDigits[(i + index) & 7u]
            ^ ((roll >> 24u) & 0xffu));
        const uint8_t s = static_cast<uint8_t>(
            stream_byte(g.journey_digest ^ mark ^ roll, static_cast<uint32_t>(i) + index, static_cast<uint8_t>(index))
            + ((roll >> 16u) & 0xffu));
        g.tail_seal[i] = static_cast<uint8_t>(
            rotl8(static_cast<uint8_t>(g.tail_seal[i] + s), index + static_cast<uint32_t>(i)) ^ mask);
    }
}

uint32_t timing_sample(uint64_t ticks, uint32_t index) {
    uint32_t sample = static_cast<uint32_t>((ticks >> 7u) ^ (ticks >> 19u) ^ (ticks >> 31u));
    sample ^= (index + 1u) * 0x27d4eb2du;
    sample ^= sample >> 13u;
    return sample;
}

void fold_live_digest(GameState& g, uint64_t ticks, uint32_t index, uint32_t mark) {
    const uint32_t sample = timing_sample(ticks, index);
    const uint64_t wide = (static_cast<uint64_t>(sample) << 32u)
        ^ static_cast<uint64_t>(mark * 0x165667b1u)
        ^ static_cast<uint64_t>((index + 1u) * 0x85ebca6bu);
    g.live_digest = mix64(g.live_digest ^ wide ^ ticks);
}

uint32_t head_key(uint32_t height_m) {
    return (height_m * 0x045d9f3bu) ^ kFoundingDate ^ 0x53554d4du;
}

size_t recover_head(char* out, size_t out_cap, uint32_t height_m) {
    constexpr std::array<uint8_t, 28> enc = {
        21, 243, 92, 92, 135, 255, 185, 153, 221, 16,
        56, 252, 252, 98, 119, 102, 160, 152, 219, 127,
        121, 92, 227, 243, 64, 31, 56, 74,
    };

    const uint32_t key = head_key(height_m);
    const size_t n = std::min(enc.size(), out_cap ? out_cap - 1u : 0u);
    for (size_t i = 0; i < n; ++i) {
        out[i] = static_cast<char>(unseal_byte(enc[i], key, static_cast<uint32_t>(i), 0x21u));
    }
    if (out_cap) {
        out[n] = '\0';
    }
    return n;
}

uint32_t folded_live(const GameState& g) {
    return static_cast<uint32_t>(g.live_digest ^ (g.live_digest >> 32u));
}

uint8_t stone_round_key(uint32_t state, uint32_t index, uint8_t lane, uint32_t round) {
    return static_cast<uint8_t>(
        (stream_byte(state ^ ((round + 1u) * 0x045d9f3bu), index + round * 3u, static_cast<uint8_t>(lane + round * 17u))
            ^ (state >> ((round & 3u) * 8u)))
        & 0x0fu);
}

uint8_t feistel_unwrap(uint8_t v, uint32_t state, uint32_t index, uint8_t lane) {
    uint8_t left = static_cast<uint8_t>((v >> 4u) & 0x0fu);
    uint8_t right = static_cast<uint8_t>(v & 0x0fu);
    for (int round = 3; round >= 0; --round) {
        const uint8_t prev_right = left;
        const uint8_t f = static_cast<uint8_t>(
            (prev_right * 5u + stone_round_key(state, index, lane, static_cast<uint32_t>(round)) + round * 3u) & 0x0fu);
        const uint8_t prev_left = static_cast<uint8_t>(right ^ f);
        left = prev_left;
        right = prev_right;
    }
    return static_cast<uint8_t>((left << 4u) | right);
}

uint8_t run_tail_vm(const GameState& g, uint32_t index, uint32_t state, uint8_t lane) {
    constexpr std::array<uint8_t, 11> bytecode = {
        160, 251, 255, 207, 222, 232, 112, 14, 49, 228, 73,
    };

    constexpr uint8_t kLoadSeal = 0x31u;
    constexpr uint8_t kMakeA = 0x42u;
    constexpr uint8_t kMakeB = 0x53u;
    constexpr uint8_t kRorByB = 0x64u;
    constexpr uint8_t kMixAB = 0x75u;
    constexpr uint8_t kSubB = 0x86u;
    constexpr uint8_t kRorByA = 0x97u;
    constexpr uint8_t kSubA = 0xa8u;
    constexpr uint8_t kCoreRound = 0xd2u;
    constexpr uint8_t kStore = 0xb9u;
    constexpr uint8_t kStop = 0xc1u;

    const uint32_t vm_key = g.ball.scar ^ g.journey_digest ^ folded_live(g) ^ 0x5eedc0deu;
    uint8_t acc = 0;
    uint8_t a = 0;
    uint8_t b = 0;
    uint8_t stored = 0;

    for (size_t ip = 0; ip < bytecode.size(); ++ip) {
        const uint8_t op = static_cast<uint8_t>(bytecode[ip] ^ stream_byte(vm_key, static_cast<uint32_t>(ip), 0x5cu));
        switch (op) {
            case kLoadSeal:
                acc = tail_seal_byte(g, index);
                break;
            case kMakeA:
                a = stream_byte(state, index, lane);
                break;
            case kMakeB:
                b = stream_byte(state ^ 0xa5a5a5a5u, index + 7u, static_cast<uint8_t>(lane ^ 5u));
                break;
            case kRorByB:
                acc = rotr8(acc, (static_cast<uint32_t>(b >> 3u) + lane) & 7u);
                break;
            case kMixAB:
                acc = static_cast<uint8_t>(acc ^ static_cast<uint8_t>(a + b + index));
                break;
            case kSubB:
                acc = static_cast<uint8_t>(acc - b - 0x3du);
                break;
            case kRorByA:
                acc = rotr8(acc, (static_cast<uint32_t>(a ^ index ^ lane) & 7u));
                break;
            case kSubA:
                acc = static_cast<uint8_t>(acc - a - index * 13u);
                break;
            case kCoreRound:
                acc = feistel_unwrap(acc, state, index, lane);
                break;
            case kStore:
                stored = acc;
                break;
            case kStop:
                return stored;
            default:
                acc = stream_byte(state ^ vm_key, static_cast<uint32_t>(ip) + index, static_cast<uint8_t>(acc ^ lane));
                break;
        }
    }

    return stored;
}

size_t recover_tail(const GameState& g, char* out, size_t out_cap) {
    const size_t n = std::min(g.tail_seal.size(), out_cap ? out_cap - 1u : 0u);
    for (size_t i = 0; i < n; ++i) {
        const uint32_t state = g.ball.scar
            ^ g.journey_digest
            ^ folded_live(g)
            ^ (static_cast<uint32_t>(g.ball.core[i & 15u]) << 24u)
            ^ ((g.resets + static_cast<uint32_t>(i) + 1u) * 0x7f4a7c15u);
        out[i] = static_cast<char>(run_tail_vm(
            g,
            static_cast<uint32_t>(i),
            state,
            g.ball.core[(i + 5u) & 15u]));
    }
    if (out_cap) {
        out[n] = '\0';
    }
    return n;
}

bool is_worthy(const GameState& g) {
    volatile uint32_t h = g.climb_peak_m;
    return h >= kTargetMeters;
}

bool carve_stone(GameState& g, uint64_t ticks) {
    if (g.resets >= kTargetResets || !g.checkpoint_seen || g.climb_peak_m < g.checkpoint_m) {
        return false;
    }

    const uint32_t index = g.resets;
    const uint32_t mark = kRiteMeters[index];
    g.resets += 1;
    g.journey_digest = journey_step(g.journey_digest, index, mark);
    fold_live_digest(g, ticks, index, mark);
    turn_tail_seal(g, index, mark);

    const uint32_t mix = kFoundingDate
        ^ (mark * 0x045d9f3bu)
        ^ (g.resets * 0x119de1f3u)
        ^ (static_cast<uint32_t>(g.ball.core[index & 15u]) << 24u);
    g.ball.scar = rotl32(g.ball.scar ^ mix, kFoundingDigits[index & 7u] + g.resets) + 0x9e3779b9u;

    for (size_t i = 0; i < g.ball.core.size(); ++i) {
        const uint8_t lane = static_cast<uint8_t>((g.ball.scar >> ((i & 3u) * 8u)) & 0xffu);
        const uint8_t date = kFoundingDigits[(i + index) & 7u];
        const uint8_t stone = static_cast<uint8_t>((mark >> ((i & 1u) * 8u)) & 0xffu);
        g.ball.core[i] = rotl8(
            static_cast<uint8_t>(g.ball.core[i] ^ lane ^ stone ^ static_cast<uint8_t>(date * 17u + g.resets)),
            date + static_cast<uint32_t>(i) + g.resets);
    }

    g.checkpoint_digest = journey_step(
        g.checkpoint_digest,
        index,
        g.checkpoint_m
            ^ static_cast<uint32_t>(g.checkpoint_x * 17.0f)
            ^ static_cast<uint32_t>(g.run_seed >> ((index & 1u) * 32u)));
    if (g.resets == kTargetResets) {
        bind_tail_to_checkpoints(g);
    }
    choose_checkpoint(g);
    return true;
}

void reset_ball(GameState& g, bool try_carve, uint64_t ticks) {
    if (try_carve) {
        carve_stone(g, ticks);
    }
    g.ball.x = 70.0f;
    g.ball.vx = 0.0f;
    g.climb_peak_m = 0;
}

bool stone_complete(const GameState& g) {
    volatile uint32_t scar = g.ball.scar;
    volatile uint32_t journey = g.journey_digest;
    const uint64_t live_gate = mix64(g.live_digest ^ (static_cast<uint64_t>(scar) << 32u) ^ journey);
    return g.resets == kTargetResets
        && scar == 0x7f5f4734u
        && journey == 0x714b5c73u
        && live_gate == 0x9351ab846dbebf66ull;
}

void draw_filled_circle(SDL_Renderer* r, int cx, int cy, int radius) {
    for (int y = -radius; y <= radius; ++y) {
        const int span = static_cast<int>(std::sqrt(static_cast<float>(radius * radius - y * y)));
        SDL_RenderDrawLine(r, cx - span, cy + y, cx + span, cy + y);
    }
}

void draw_scene(SDL_Renderer* renderer, const GameState& g) {
    SDL_SetRenderDrawColor(renderer, 18, 21, 28, 255);
    SDL_RenderClear(renderer);

    SDL_SetRenderDrawColor(renderer, 47, 55, 67, 255);
    for (int y = 72; y < kScreenH; y += 48) {
        SDL_RenderDrawLine(renderer, 0, y, kScreenW, y);
    }

    SDL_SetRenderDrawColor(renderer, 180, 180, 174, 255);
    int prev_x = screen_x(kWorldLeft);
    int prev_y = screen_y(terrain_height_m(kWorldLeft));
    for (int i = 1; i <= 220; ++i) {
        const float wx = kWorldLeft + (kWorldRight - kWorldLeft) * (static_cast<float>(i) / 220.0f);
        const int sx = screen_x(wx);
        const int sy = screen_y(terrain_height_m(wx));
        SDL_RenderDrawLine(renderer, prev_x, prev_y, sx, sy);
        SDL_RenderDrawLine(renderer, prev_x, prev_y + 1, sx, sy + 1);
        prev_x = sx;
        prev_y = sy;
    }

    const float ball_h = terrain_height_m(g.ball.x);
    const int bx = screen_x(g.ball.x);
    const int by = screen_y(ball_h) - static_cast<int>(g.ball.radius);

    SDL_SetRenderDrawColor(renderer, 209, 70, 62, 255);
    draw_filled_circle(renderer, bx, by, static_cast<int>(g.ball.radius));

    SDL_SetRenderDrawColor(renderer, 240, 219, 137, 255);
    SDL_Rect summit = {screen_x(kSummitX) - 4, screen_y(kSummitMeters) - 46, 8, 46};
    SDL_RenderFillRect(renderer, &summit);

    SDL_RenderPresent(renderer);
}

void update_title(SDL_Window* window, const GameState& g) {
    char title[256];
    std::snprintf(
        title,
        sizeof(title),
        "Sisypush | height %um | scars %u | arrows or A/D push, Space strain, R reset",
        g.max_height_m,
        g.resets);
    SDL_SetWindowTitle(window, title);
}

void update_game(GameState& g, float dt, const uint8_t* keys, uint64_t ticks) {
    float input = 0.0f;
    if (keys[SDL_SCANCODE_LEFT] || keys[SDL_SCANCODE_A]) {
        input -= 1.0f;
    }
    if (keys[SDL_SCANCODE_RIGHT] || keys[SDL_SCANCODE_D]) {
        input += 1.0f;
    }

    const float slope = terrain_slope_m_per_px(g.ball.x);
    const float gravity_pull = -0.30f * slope;
    const float player_push = input * 0.46f;
    const float futile_strain = keys[SDL_SCANCODE_SPACE] ? 0.10f : 0.0f;

    const float prev_x = g.ball.x;
    g.ball.vx += (gravity_pull + player_push + futile_strain) * dt * 60.0f;
    g.ball.vx *= std::pow(0.988f, dt * 60.0f);
    g.ball.x += g.ball.vx * dt * 60.0f;

    if (g.ball.x < 35.0f) {
        g.ball.x = 35.0f;
        g.ball.vx *= -0.15f;
    }

    if (g.ball.x > kWorldRight - 35.0f) {
        g.ball.x = kWorldRight - 35.0f;
        g.ball.vx *= -0.4f;
    }

    uint32_t h = static_cast<uint32_t>(terrain_height_m(g.ball.x) + 0.5f);
    if ((prev_x <= kSummitX && g.ball.x >= kSummitX) || (prev_x >= kSummitX && g.ball.x <= kSummitX)) {
        h = kTargetMeters;
    }
    g.max_height_m = std::max(g.max_height_m, h);
    g.climb_peak_m = std::max(g.climb_peak_m, h);

    if (g.resets < kTargetResets && !g.checkpoint_seen) {
        const float lo = std::min(prev_x, g.ball.x) - g.ball.radius * 0.35f;
        const float hi = std::max(prev_x, g.ball.x) + g.ball.radius * 0.35f;
        if (g.checkpoint_x >= lo && g.checkpoint_x <= hi && h >= g.checkpoint_m) {
            g.checkpoint_seen = true;
        }
    }

    if (g.ball.x < 95.0f && g.climb_peak_m > 300u && std::abs(g.ball.vx) < 0.35f) {
        reset_ball(g, true, ticks);
    }
}

}  // namespace

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;

    SDL_SetMainReady();
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER) != 0) {
        std::fprintf(stderr, "SDL_Init failed: %s\n", SDL_GetError());
        return 1;
    }

    SDL_Window* window = SDL_CreateWindow(
        "Sisypush",
        SDL_WINDOWPOS_CENTERED,
        SDL_WINDOWPOS_CENTERED,
        kScreenW,
        kScreenH,
        SDL_WINDOW_SHOWN);
    if (!window) {
        std::fprintf(stderr, "SDL_CreateWindow failed: %s\n", SDL_GetError());
        SDL_Quit();
        return 1;
    }

    SDL_Renderer* renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
    if (!renderer) {
        std::fprintf(stderr, "SDL_CreateRenderer failed: %s\n", SDL_GetError());
        SDL_DestroyWindow(window);
        SDL_Quit();
        return 1;
    }

    GameState game;
    initialize_run(game, SDL_GetPerformanceCounter());
    bool running = true;
    uint64_t last = SDL_GetPerformanceCounter();

    while (running) {
        SDL_Event e;
        while (SDL_PollEvent(&e)) {
            if (e.type == SDL_QUIT) {
                running = false;
            } else if (e.type == SDL_KEYDOWN && e.key.keysym.sym == SDLK_ESCAPE) {
                running = false;
            } else if (e.type == SDL_KEYDOWN && e.key.keysym.sym == SDLK_r) {
                reset_ball(game, false, SDL_GetPerformanceCounter());
            }
        }

        const uint64_t now = SDL_GetPerformanceCounter();
        const double freq = static_cast<double>(SDL_GetPerformanceFrequency());
        const float dt = clampf(static_cast<float>((now - last) / freq), 0.0f, 0.033f);
        last = now;

        const uint8_t* keys = SDL_GetKeyboardState(nullptr);
        update_game(game, dt, keys, now);

        if (is_worthy(game) && stone_complete(game) && !game.full_revealed) {
            game.full_revealed = true;
            char message[64];
            const size_t head_len = recover_head(message, sizeof(message), game.climb_peak_m);
            recover_tail(game, message + head_len, sizeof(message) - head_len);
            SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_INFORMATION, "The stone remembers.", message, window);
        } else if (is_worthy(game) && !game.head_revealed) {
            game.head_revealed = true;
            char message[32];
            recover_head(message, sizeof(message), game.climb_peak_m);
            SDL_ShowSimpleMessageBox(SDL_MESSAGEBOX_INFORMATION, "The stone rests.", message, window);
        }

        update_title(window, game);
        draw_scene(renderer, game);
    }

    SDL_DestroyRenderer(renderer);
    SDL_DestroyWindow(window);
    SDL_Quit();
    return 0;
}
