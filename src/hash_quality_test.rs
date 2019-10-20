use core::hash::{Hash, Hasher};

fn assert_sufficiently_different(a: u64, b: u64, tolerance: i32) {
    let (same_byte_count, same_nibble_count) = count_same_bytes_and_nibbles(a, b);
    assert!(same_byte_count <= tolerance, "{:x} vs {:x}: {:}", a, b, same_byte_count);
    assert!(
        same_nibble_count <= tolerance * 3,
        "{:x} vs {:x}: {:}",
        a,
        b,
        same_nibble_count
    );
    let flipped_bits = (a ^ b).count_ones();
    assert!(
        flipped_bits > 12 && flipped_bits < 52,
        "{:x} and {:x}: {:}",
        a,
        b,
        flipped_bits
    );
    for rotate in 0..64 {
        let flipped_bits2 = (a ^ (b.rotate_left(rotate))).count_ones();
        assert!(
            flipped_bits2 > 10 && flipped_bits2 < 54,
            "{:x} and {:x}: {:}",
            a,
            b.rotate_left(rotate),
            flipped_bits2
        );
    }
}

fn count_same_bytes_and_nibbles(a: u64, b: u64) -> (i32, i32) {
    let mut same_byte_count = 0;
    let mut same_nibble_count = 0;
    for byte in 0..8 {
        let ba = (a >> (8 * byte)) as u8;
        let bb = (b >> (8 * byte)) as u8;
        if ba == bb {
            same_byte_count += 1;
        }
        if ba & 0xF0u8 == bb & 0xF0u8 {
            same_nibble_count += 1;
        }
        if ba & 0x0Fu8 == bb & 0x0Fu8 {
            same_nibble_count += 1;
        }
    }
    (same_byte_count, same_nibble_count)
}

fn test_keys_change_output<T: Hasher>(constructor: impl Fn(u64, u64) -> T) {
    let mut a = constructor(0, 0);
    let mut b = constructor(0, 1);
    let mut c = constructor(1, 0);
    let mut d = constructor(1, 1);
    "test".hash(&mut a);
    "test".hash(&mut b);
    "test".hash(&mut c);
    "test".hash(&mut d);
    assert_sufficiently_different(a.finish(), b.finish(), 1);
    assert_sufficiently_different(a.finish(), c.finish(), 1);
    assert_sufficiently_different(a.finish(), d.finish(), 1);
    assert_sufficiently_different(b.finish(), c.finish(), 1);
    assert_sufficiently_different(b.finish(), d.finish(), 1);
    assert_sufficiently_different(c.finish(), d.finish(), 1);
}

fn test_input_affect_every_byte<T: Hasher>(constructor: impl Fn(u64, u64) -> T) {
    let mut base = constructor(0, 0);
    0.hash(&mut base);
    let base = base.finish();
    for shift in 0..16 {
        let mut alternitives = vec![];
        for v in 0..256 {
            let input = (v as u128) << (shift * 8);
            let mut hasher = constructor(0, 0);
            input.hash(&mut hasher);
            alternitives.push(hasher.finish());
        }
        assert_each_byte_differes(base, alternitives);
    }
}

fn test_keys_affect_every_byte<T: Hasher>(constructor: impl Fn(u64, u64) -> T) {
    let mut base = constructor(0, 0);
    0.hash(&mut base);
    let base = base.finish();
    for shift in 0..8 {
        let mut alternitives1 = vec![];
        let mut alternitives2 = vec![];
        for v in 0..256 {
            let input = (v as u64) << (shift * 8);
            let mut hasher1 = constructor(input, 0);
            let mut hasher2 = constructor(0, input);
            0.hash(&mut hasher1);
            0.hash(&mut hasher2);
            alternitives1.push(hasher1.finish());
            alternitives2.push(hasher2.finish());
        }
        assert_each_byte_differes(base, alternitives1);
        assert_each_byte_differes(base, alternitives2);
    }
}

fn assert_each_byte_differes(base: u64, alternitives: Vec<u64>) {
    let mut changed_bits = 0_u64;
    for alternitive in alternitives {
        changed_bits |= base ^ alternitive
    }
    assert_eq!(core::u64::MAX, changed_bits, "Bits changed: {:x}", changed_bits);
}

fn test_finish_is_consistant<T: Hasher>(constructor: impl Fn(u64, u64) -> T) {
    let mut hasher = constructor(1, 2);
    "Foo".hash(&mut hasher);
    let a = hasher.finish();
    let b = hasher.finish();
    assert_eq!(a, b);
}

fn test_single_key_bit_flip<T: Hasher>(constructor: impl Fn(u64, u64) -> T) {
    for bit in 0..64 {
        let mut a = constructor(0, 0);
        let mut b = constructor(0, 1 << bit);
        let mut c = constructor(1 << bit, 0);
        "1234".hash(&mut a);
        "1234".hash(&mut b);
        "1234".hash(&mut c);
        assert_sufficiently_different(a.finish(), b.finish(), 2);
        assert_sufficiently_different(a.finish(), c.finish(), 2);
        assert_sufficiently_different(b.finish(), c.finish(), 2);
        let mut a = constructor(0, 0);
        let mut b = constructor(0, 1 << bit);
        let mut c = constructor(1 << bit, 0);
        "12345678".hash(&mut a);
        "12345678".hash(&mut b);
        "12345678".hash(&mut c);
        assert_sufficiently_different(a.finish(), b.finish(), 2);
        assert_sufficiently_different(a.finish(), c.finish(), 2);
        assert_sufficiently_different(b.finish(), c.finish(), 2);
        let mut a = constructor(0, 0);
        let mut b = constructor(0, 1 << bit);
        let mut c = constructor(1 << bit, 0);
        "1234567812345678".hash(&mut a);
        "1234567812345678".hash(&mut b);
        "1234567812345678".hash(&mut c);
        assert_sufficiently_different(a.finish(), b.finish(), 2);
        assert_sufficiently_different(a.finish(), c.finish(), 2);
        assert_sufficiently_different(b.finish(), c.finish(), 2);
    }
}

fn test_all_bytes_matter<T: Hasher>(hasher: impl Fn() -> T) {
    let mut item = vec![0; 256];
    let base_hash = hash(&item, &hasher);
    for pos in 0..256 {
        item[pos] = 255;
        let hash = hash(&item, &hasher);
        assert_ne!(base_hash, hash, "Position {} did not affect output", pos);
        item[pos] = 0;
    }
}

fn hash<T: Hasher>(b: &impl Hash, hasher: &dyn Fn() -> T) -> u64 {
    let mut hasher = hasher();
    b.hash(&mut hasher);
    hasher.finish()
}

fn test_single_bit_flip<T: Hasher>(hasher: impl Fn() -> T) {
    let size = 32;
    let compare_value = hash(&0u32, &hasher);
    for pos in 0..size {
        let test_value = hash(&(1u32 << pos), &hasher);
        assert_sufficiently_different(compare_value, test_value, 2);
    }
    let size = 64;
    let compare_value = hash(&0u64, &hasher);
    for pos in 0..size {
        let test_value = hash(&(1u64 << pos), &hasher);
        assert_sufficiently_different(compare_value, test_value, 2);
    }
    let size = 128;
    let compare_value = hash(&0u128, &hasher);
    for pos in 0..size {
        let test_value = hash(&(1u128 << pos), &hasher);
        assert_sufficiently_different(compare_value, test_value, 2);
    }
}

fn test_padding_doesnot_collide<T: Hasher>(hasher: impl Fn() -> T) {
    for c in 0..128u8 {
        for string in ["", "1234", "12345678", "1234567812345678"].iter() {
            let mut short = hasher();
            string.hash(&mut short);
            let value = short.finish();
            let mut string = string.to_string();
            for num in 1..=128 {
                let mut long = hasher();
                string.push(c as char);
                string.hash(&mut long);
                let (same_bytes, same_nibbles) = count_same_bytes_and_nibbles(value, long.finish());
                assert!(
                    same_bytes <= 2,
                    format!("{} bytes of {} -> {:x} vs {:x}", num, c, value, long.finish())
                );
                assert!(
                    same_nibbles <= 8,
                    format!("{} bytes of {} -> {:x} vs {:x}", num, c, value, long.finish())
                );
                let flipped_bits = (value ^ long.finish()).count_ones();
                assert!(flipped_bits > 10);
            }
        }
    }
}

fn test_bucket_distributin<T: Hasher>(hasher: impl Fn() -> T) {
    let sequence: Vec<_> = (0..320000).collect();
    check_for_collisions(&hasher, &sequence, 32);
    let sequence: Vec<_> = (0..2560000).collect();
    check_for_collisions(&hasher, &sequence, 256);
    let sequence: Vec<_> = (0..320000).map(|i| i * 1024).collect();
    check_for_collisions(&hasher, &sequence, 32);
    let sequence: Vec<_> = (0..2560000_u64).map(|i| i * 1024).collect();
    check_for_collisions(&hasher, &sequence, 256);
}

fn test_hash_common_words<T: Hasher>(hasher: impl Fn() -> T) {
    let words: Vec<_> = r#"
a, ability, able, about, above, accept, according, account, across, act, action,
activity, actually, add, address, administration, admit, adult, affect, after,
again, against, age, agency, agent, ago, agree, agreement, ahead, air, all,
allow, almost, alone, along, already, also, although, always, American, among,
amount, analysis, and, animal, another, answer, any, anyone, anything, appear,
apply, approach, area, argue, arm, around, arrive, art, article, artist, as,
ask, assume, at, attack, attention, attorney, audience, author, authority,
available, avoid, away, baby, back, bad, bag, ball, bank, bar, base, be, beat,
beautiful, because, become, bed, before, begin, behavior, behind, believe,
benefit, best, better, between, beyond, big, bill, billion, bit, black, blood,
blue, board, body, book, born, both, box, boy, break, bring, brother, budget,
build, building, business, but, buy, by, call, camera, campaign, can, cancer,
candidate, capital, car, card, care, career, carry, case, catch, cause, cell,
center, central, century, certain, certainly, chair, challenge, chance, change,
character, charge, check, child, choice, choose, church, citizen, city, civil,
claim, class, clear, clearly, close, coach, cold, collection, college, color,
come, commercial, common, community, company, compare, computer, concern,
condition, conference, Congress, consider, consumer, contain, continue, control,
cost, could, country, couple, course, court, cover, create, crime, cultural,
culture, cup, current, customer, cut, dark, data, daughter, day, dead, deal,
death, debate, decade, decide, decision, deep, defense, degree, Democrat,
democratic, describe, design, despite, detail, determine, develop, development,
die, difference, different, difficult, dinner, direction, director, discover,
discuss, discussion, disease, do, doctor, dog, door, down, draw, dream, drive,
drop, drug, during, each, early, east, easy, eat, economic, economy, edge,
education, effect, effort, eight, either, election, else, employee, end, energy,
enjoy, enough, enter, entire, environment, environmental, especially, establish,
even, evening, event, ever, every, everybody, everyone, everything, evidence,
exactly, example, executive, exist, expect, experience, expert, explain, eye,
face, fact, factor, fail, fall, family, far, fast, father, fear, federal, feel,
feeling, few, field, fight, figure, fill, film, final, finally, financial, find,
fine, finger, finish, fire, firm, first, fish, five, floor, fly, focus, follow,
food, foot, for, force, foreign, forget, form, former, forward, four, free,
friend, from, front, full, fund, future, game, garden, gas, general, generation,
get, girl, give, glass, go, goal, good, government, great, green, ground, group,
grow, growth, guess, gun, guy, hair, half, hand, hang, happen, happy, hard,
have, he, head, health, hear, heart, heat, heavy, help, her, here, herself,
high, him, himself, his, history, hit, hold, home, hope, hospital, hot, hotel,
hour, house, how, however, huge, human, hundred, husband, I, idea, identify, if,
image, imagine, impact, important, improve, in, include, including, increase,
indeed, indicate, individual, industry, information, inside, instead,
institution, interest, interesting, international, interview, into, investment,
involve, issue, it, item, its, itself, job, join, just, keep, key, kid, kill,
kind, kitchen, know, knowledge, land, language, large, last, late, later, laugh,
law, lawyer, lay, lead, leader, learn, least, leave, left, leg, legal, less,
let, letter, level, lie, life, light, like, likely, line, list, listen, little,
live, local, long, look, lose, loss, lot, love, low, machine, magazine, main,
maintain, major, majority, make, man, manage, management, manager, many, market,
marriage, material, matter, may, maybe, me, mean, measure, media, medical, meet,
meeting, member, memory, mention, message, method, middle, might, military,
million, mind, minute, miss, mission, model, modern, moment, money, month, more,
morning, most, mother, mouth, move, movement, movie, Mr, Mrs, much, music, must,
my, myself, name, nation, national, natural, nature, near, nearly, necessary,
need, network, never, new, news, newspaper, next, nice, night, no, none, nor,
north, not, note, nothing, notice, now, n't, number, occur, of, off, offer,
office, officer, official, often, oh, oil, ok, old, on, once, one, only, onto,
open, operation, opportunity, option, or, order, organization, other, others,
our, out, outside, over, own, owner, page, pain, painting, paper, parent, part,
participant, particular, particularly, partner, party, pass, past, patient,
pattern, pay, peace, people, per, perform, performance, perhaps, period, person,
personal, phone, physical, pick, picture, piece, place, plan, plant, play,
player, PM, point, police, policy, political, politics, poor, popular,
population, position, positive, possible, power, practice, prepare, present,
president, pressure, pretty, prevent, price, private, probably, problem,
process, produce, product, production, professional, professor, program,
project, property, protect, prove, provide, public, pull, purpose, push, put,
quality, question, quickly, quite, race, radio, raise, range, rate, rather,
reach, read, ready, real, reality, realize, really, reason, receive, recent,
recently, recognize, record, red, reduce, reflect, region, relate, relationship,
religious, remain, remember, remove, report, represent, Republican, require,
research, resource, respond, response, responsibility, rest, result, return,
reveal, rich, right, rise, risk, road, rock, role, room, rule, run, safe, same,
save, say, scene, school, science, scientist, score, sea, season, seat, second,
section, security, see, seek, seem, sell, send, senior, sense, series, serious,
serve, service, set, seven, several, sex, sexual, shake, share, she, shoot,
short, shot, should, shoulder, show, side, sign, significant, similar, simple,
simply, since, sing, single, sister, sit, site, situation, six, size, skill,
skin, small, smile, so, social, society, soldier, some, somebody, someone,
something, sometimes, son, song, soon, sort, sound, source, south, southern,
space, speak, special, specific, speech, spend, sport, spring, staff, stage,
stand, standard, star, start, state, statement, station, stay, step, still,
stock, stop, store, story, strategy, street, strong, structure, student, study,
stuff, style, subject, success, successful, such, suddenly, suffer, suggest,
summer, support, sure, surface, system, table, take, talk, task, tax, teach,
teacher, team, technology, television, tell, ten, tend, term, test, than, thank,
that, the, their, them, themselves, then, theory, there, these, they, thing,
think, third, this, those, though, thought, thousand, threat, three, through,
throughout, throw, thus, time, to, today, together, tonight, too, top, total,
tough, toward, town, trade, traditional, training, travel, treat, treatment,
tree, trial, trip, trouble, true, truth, try, turn, TV, two, type, under,
understand, unit, until, up, upon, us, use, usually, value, various, very,
victim, view, violence, visit, voice, vote, wait, walk, wall, want, war, watch,
water, way, we, weapon, wear, week, weight, well, west, western, what, whatever,
when, where, whether, which, while, white, who, whole, whom, whose, why, wide,
wife, will, win, wind, window, wish, with, within, without, woman, wonder, word,
work, worker, world, worry, would, write, writer, wrong, yard, yeah, year, yes,
yet, you, young, your, yourself"#
        .split(',')
        .map(|word| word.trim())
        .collect();

    let mut word_pairs: Vec<_> = Vec::new();
    for word in &words {
        for other_word in &words {
            word_pairs.push(word.to_string() + " " + other_word);
        }
    }

    check_for_collisions(&hasher, &word_pairs, 32);
}

fn check_for_collisions<T: Hasher, H: Hash>(hasher: &impl Fn() -> T, items: &[H], bucket_count: usize) {
    let mut buckets = vec![0; bucket_count];
    for item in items {
        let value = hash(item, &hasher) as usize;
        println!("{:x}", value);
        buckets[value % bucket_count] += 1;
    }
    let mean = items.len() / bucket_count;
    let max = *buckets.iter().max().unwrap();
    let min = *buckets.iter().min().unwrap();
    assert!((min as f64) > (mean as f64) * 0.95, "min: {}, max:{}, {:?}", min, max, buckets);
    assert!((max as f64) < (mean as f64) * 1.05, "min: {}, max:{}, {:?}", min, max, buckets);
}

#[cfg(test)]
mod fallback_tests {
    use crate::fallback_hash::*;
    use crate::hash_quality_test::*;

    #[test]
    fn fallback_single_bit_flip() {
        test_single_bit_flip(|| AHasher::test_with_keys(0, 0))
    }

    #[test]
    fn fallback_single_key_bit_flip() {
        test_single_key_bit_flip(AHasher::test_with_keys)
    }

    #[test]
    fn fallback_all_bytes_matter() {
        test_all_bytes_matter(|| AHasher::test_with_keys(0, 0));
    }

    #[test]
    fn fallback_keys_change_output() {
        test_keys_change_output(AHasher::test_with_keys);
    }

    #[test]
    fn fallback_input_affect_every_byte() {
        test_input_affect_every_byte(AHasher::test_with_keys);
    }

    #[test]
    fn fallback_keys_affect_every_byte() {
        test_keys_affect_every_byte(AHasher::test_with_keys);
    }

    #[test]
    fn fallback_finish_is_consistant() {
        test_finish_is_consistant(AHasher::test_with_keys)
    }

    #[test]
    fn fallback_padding_doesnot_collide() {
        test_padding_doesnot_collide(|| AHasher::test_with_keys(0, 1))
    }

    #[test]
    fn fallback_bucket_distributin() {
        test_bucket_distributin(|| AHasher::test_with_keys(0x0123456789ABCDEF, 0x0123456789ABCDEF))
    }

    #[test]
    fn fallback_word_distribution() {
        test_hash_common_words(|| AHasher::test_with_keys(0x0123456789ABCDEF, 0x0123456789ABCDEF))
    }
}

///Basic sanity tests of the cypto properties of aHash.
#[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "aes"))]
#[cfg(test)]
mod aes_tests {
    use crate::aes_hash::*;
    use crate::hash_quality_test::*;
    use std::hash::{Hash, Hasher};

    const BAD_KEY: u64 = 0x5252_5252_5252_5252; //Thi   s encrypts to 0.

    #[test]
    fn test_single_bit_in_byte() {
        let mut hasher1 = AHasher::new_with_keys(64, 64);
        8_u32.hash(&mut hasher1);
        let mut hasher2 = AHasher::new_with_keys(64, 64);
        0_u32.hash(&mut hasher2);
        assert_sufficiently_different(hasher1.finish(), hasher2.finish(), 1);
    }

    #[test]
    fn aes_single_bit_flip() {
        test_single_bit_flip(|| AHasher::test_with_keys(BAD_KEY, BAD_KEY))
    }

    #[test]
    fn aes_single_key_bit_flip() {
        test_single_key_bit_flip(|k1, k2| AHasher::test_with_keys(k1, k2))
    }

    #[test]
    fn aes_all_bytes_matter() {
        test_all_bytes_matter(|| AHasher::test_with_keys(BAD_KEY, BAD_KEY));
    }

    #[test]
    fn aes_keys_change_output() {
        test_keys_change_output(AHasher::test_with_keys);
    }

    #[test]
    fn aes_input_affect_every_byte() {
        test_input_affect_every_byte(AHasher::test_with_keys);
    }

    #[test]
    fn aes_keys_affect_every_byte() {
        test_keys_affect_every_byte(AHasher::test_with_keys);
    }
    #[test]
    fn aes_finish_is_consistant() {
        test_finish_is_consistant(AHasher::test_with_keys)
    }

    #[test]
    fn aes_padding_doesnot_collide() {
        test_padding_doesnot_collide(|| AHasher::test_with_keys(BAD_KEY, BAD_KEY))
    }

    #[test]
    fn aes_bucket_distributin() {
        test_bucket_distributin(|| AHasher::test_with_keys(0x0123456789ABCDEF, 0x0123456789ABCDEF))
    }

    #[test]
    fn aes_word_distribution() {
        test_hash_common_words(|| AHasher::test_with_keys(0x0123456789ABCDEF, 0x0123456789ABCDEF))
    }
}
