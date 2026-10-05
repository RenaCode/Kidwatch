/* Lista odbiorcow WhatsApp w Profilu. Repo jest publiczne: tylko fikcyjne numery. */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  partialFailure, recipientsFromState, recipientsPayload, sameRecipients, testSummary,
  validateRecipients,
  digits, getsEverything, newRecipient, sourcesLabel,
} from './recipients.js';

const A = '48500100200';
const B = '48500100300';

test('stan z bramki -> wiersze edytora, takze ze starej bramki', () => {
  assert.deepEqual(
    recipientsFromState({ odbiorcy: [{ numer: A, etykieta: 'Ja', aktywny: true },
                                     { numer: B, etykieta: '', aktywny: false }] }),
    [{ number: A, label: 'Ja', active: true, sources: null },
     { number: B, label: '', active: false, sources: null }],
  );
  assert.deepEqual(recipientsFromState({ odbiorca: A }),
    [{ number: A, label: '', active: true, sources: null }]);
  assert.deepEqual(recipientsFromState({ odbiorcy: [], odbiorca: '' }), []);
  assert.deepEqual(recipientsFromState(null), []);
});

test('walidacja: format, duplikaty po cyfrach, limit, etykieta', () => {
  assert.equal(validateRecipients([{ number: `+48 500 100 200`, label: 'Ja', active: true }]), null);
  assert.match(validateRecipients([{ number: '123', label: '', active: true }]), /^Odbiorca 1: numer/);
  assert.match(
    validateRecipients([{ number: A, label: '', active: true }, { number: '+48 500 100 200', label: '', active: false }]),
    /^Odbiorca 2: ten numer/,
  );
  const six = Array.from({ length: 6 }, (_, i) => ({ number: `4850010030${i}`, label: '', active: true }));
  assert.match(validateRecipients(six), /Najwyżej 5/);
  assert.match(validateRecipients([{ number: A, label: 'x'.repeat(41), active: true }]), /40 znaków/);
  assert.equal(validateRecipients([]), null);
});

test('cialo zadania i wykrywanie zmian', () => {
  const list = [{ number: '+48 500 100 200', label: ' Ja ', active: true }];
  assert.deepEqual(recipientsPayload(list), [{ number: A, label: 'Ja', active: true }]);
  assert.equal(sameRecipients(list, [{ number: A, label: 'Ja', active: true }]), true);
  assert.equal(sameRecipients(list, [{ number: A, label: 'Ja', active: false }]), false);
});

test('podsumowanie wiadomosci probnej', () => {
  assert.equal(testSummary({ ok: true, kanal: 'whatsapp', bledy: {}, odbiorcy: { doszlo: 2, wszystkich: 2 } }),
    'WhatsApp: doszło do 2 z 2.');
  const czesc = { ok: true, kanal: 'whatsapp', bledy: { whatsapp: 'nie doszlo do 1 z 2: ...300: WAHA 500' },
                  odbiorcy: { doszlo: 1, wszystkich: 2 } };
  assert.match(testSummary(czesc), /^WhatsApp: doszło do 1 z 2\. Nie doszło: .*\.\.\.300/);
  assert.equal(partialFailure(czesc), true);
  assert.equal(testSummary({ ok: true, kanal: 'email', bledy: {} }), 'Wysłano e-mailem.');
  assert.equal(partialFailure({ ok: true, kanal: 'email', bledy: { whatsapp: 'x' } }), false);
});

test('numer: tylko cyfry ASCII, + i separatory; 00 to prefiks miedzynarodowy', () => {
  assert.equal(digits('0048 600-100-200'), '48600100200');
  assert.equal(digits('+48 600 100 200'), '48600100200');
  assert.match(validateRecipients([{ number: '+48 600-100-200 wew. 12', label: '', active: true }]),
    /^Odbiorca 1: tylko cyfry/);
  assert.match(validateRecipients([{ number: '+١٢٣٤٥٦٧٨٩٠١', label: '', active: true }]),
    /^Odbiorca 1: tylko cyfry/);
});

test('trasy: z bramki, do zapisu, opis i nowy wiersz', () => {
  const stan = { odbiorcy: [{ numer: A, etykieta: 'Ja', aktywny: true, zrodla: ['*'] },
                            { numer: B, etykieta: 'Rodzina', aktywny: true, zrodla: ['kidwatch'] }],
                 zrodla_rodziny: ['kidwatch'] };
  const lista = recipientsFromState(stan);
  assert.deepEqual(lista.map((r) => r.sources), [['*'], ['kidwatch']]);
  assert.deepEqual(recipientsPayload(lista).map((r) => r.sources), [['*'], ['kidwatch']]);
  assert.equal(sourcesLabel(['*']), 'wszystko');
  assert.equal(sourcesLabel(['kidwatch']), 'tylko kidwatch (dzieci)');
  assert.equal(sourcesLabel(['kidwatch', 'trader']), 'kidwatch, trader');
  assert.equal(sourcesLabel(null), 'wszystko');
  assert.deepEqual(lista.map(getsEverything), [true, false]);
  // Nowa osoba na liscie dostaje domyslnie tylko kidwatch.
  assert.deepEqual(newRecipient(stan).sources, ['kidwatch']);
  // Zmiana tras to zmiana listy.
  assert.equal(sameRecipients(lista, [lista[0], { ...lista[1], sources: ['*'] }]), false);
});

test('bramka sprzed tras: pole sources nie idzie w zapisie', () => {
  const lista = recipientsFromState({ odbiorcy: [{ numer: A, etykieta: '', aktywny: true }] });
  assert.equal('sources' in recipientsPayload(lista)[0], false);
  assert.equal(newRecipient({ odbiorcy: [{ numer: A }] }).sources, null);
  assert.equal(getsEverything(lista[0]), true);
});
