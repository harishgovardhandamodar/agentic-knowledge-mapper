import { describe, expect, it } from 'vitest';
import { benchApiBase, chatLink } from './config';

describe('benchApiBase', () => {
  it('defaults to same-origin (empty) when no override is configured', () => {
    expect(benchApiBase(undefined)).toBe('');
    expect(benchApiBase('')).toBe('');
  });
  it('passes an explicit override through and strips trailing slashes', () => {
    expect(benchApiBase('http://api.example.com:5250')).toBe('http://api.example.com:5250');
    expect(benchApiBase('http://api.example.com:5250/')).toBe('http://api.example.com:5250');
  });
});

describe('chatLink', () => {
  it('points at Open WebUI on the same host, port 8080', () => {
    expect(chatLink('example.com')).toBe('http://example.com:8080');
    expect(chatLink('localhost')).toBe('http://localhost:8080');
  });
  it('falls back to localhost for empty/invalid hostnames', () => {
    expect(chatLink('')).toBe('http://localhost:8080');
  });
});