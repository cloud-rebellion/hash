import { expect, test } from 'bun:test';
import { checkedCRMContext, checkedCRMObservation } from './crmDocument';
import { crmContextFixture, crmObservationFixture } from './crmDocument.test';

test('CRM comparison preserves absent versus explicitly empty without accepting null', () => {
  const base = crmContextFixture();
  const absent = { ...base, variables: [{ ...base.variables[0], required: false, current_value: '', current_present: false }] };
  const empty = { ...base, variables: [{ ...absent.variables[0], current_present: true }] };
  expect(checkedCRMContext(absent).variables[0].current_present).toBe(false);
  expect(checkedCRMContext(empty).variables[0].current_present).toBe(true);
  expect(() => checkedCRMContext({ ...absent, variables: [{ ...absent.variables[0], current_value: 'undeclared replacement' }] })).toThrow();
  expect(() => checkedCRMContext({ ...empty, variables: [{ ...empty.variables[0], current_present: null }] })).toThrow();
  const observation = crmObservationFixture(absent, '');
  expect(checkedCRMObservation(observation).items[0]).toMatchObject({ current_present: false, current_value: '', available: true, value: '' });
  expect(() => checkedCRMObservation({ ...observation, items: [{ ...observation.items[0], value: null }] })).toThrow();
  expect(() => checkedCRMObservation({ ...observation, items: [{ ...observation.items[0], current_present: false, current_value: 'hidden old value' }] })).toThrow();
});
