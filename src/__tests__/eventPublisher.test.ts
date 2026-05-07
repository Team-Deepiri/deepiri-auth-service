/**
 * Tests for Auth Service event publisher.
 *
 * Verifies correct event shape is published for each user lifecycle action,
 * and that Redis errors never propagate as HTTP errors.
 */

const mockConnect  = jest.fn().mockResolvedValue(undefined);
const mockPublish  = jest.fn().mockResolvedValue(undefined);
const mockSubscribe = jest.fn();
const mockDisconnect = jest.fn();

jest.mock('@team-deepiri/shared-utils', () => ({
  StreamingClient: jest.fn().mockImplementation(() => ({
    connect:    mockConnect,
    disconnect: mockDisconnect,
    subscribe:  mockSubscribe,
    publish:    mockPublish,
  })),
  StreamTopics: {
    PLATFORM_EVENTS: 'platform-events',
  },
  secureLog: jest.fn(),
  validateSecret: jest.fn().mockReturnValue('mock-secret-32-characters-long!!'),
}), { virtual: true });

describe('Auth eventPublisher', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.resetModules();
  });

  async function getPublisher() {
    return require('../streaming/eventPublisher');
  }

  describe('publishUserRegistered', () => {
    it('publishes user-registered event with userId and email', async () => {
      const { publishUserRegistered } = await getPublisher();
      await publishUserRegistered('uid-1', 'test@example.com');

      expect(mockPublish).toHaveBeenCalledWith(
        'platform-events',
        expect.objectContaining({
          event:   'user-registered',
          user_id: 'uid-1',
          data:    expect.objectContaining({ email: 'test@example.com' }),
        })
      );
    });

    it('includes ISO timestamp and source fields', async () => {
      const { publishUserRegistered } = await getPublisher();
      await publishUserRegistered('uid-2', 'x@y.com');
      const published = mockPublish.mock.calls[0][1];
      expect(published.source).toBe('auth-service');
      expect(new Date(published.timestamp).getTime()).not.toBeNaN();
    });
  });

  describe('publishUserLogin', () => {
    it('publishes user-login event', async () => {
      const { publishUserLogin } = await getPublisher();
      await publishUserLogin('uid-3');
      expect(mockPublish).toHaveBeenCalledWith(
        'platform-events',
        expect.objectContaining({ event: 'user-login', user_id: 'uid-3' })
      );
    });
  });

  describe('publishUserLogout', () => {
    it('publishes user-logout event', async () => {
      const { publishUserLogout } = await getPublisher();
      await publishUserLogout('uid-4');
      expect(mockPublish).toHaveBeenCalledWith(
        'platform-events',
        expect.objectContaining({ event: 'user-logout', user_id: 'uid-4' })
      );
    });
  });

  describe('error resilience', () => {
    it('does not throw when Redis publish fails', async () => {
      mockPublish.mockRejectedValueOnce(new Error('Redis connection refused'));
      const { publishUserLogin } = await getPublisher();
      await expect(publishUserLogin('uid-5')).resolves.not.toThrow();
    });

    it('does not throw when Redis connect fails', async () => {
      mockConnect.mockRejectedValueOnce(new Error('ECONNREFUSED'));
      const { publishUserRegistered } = await getPublisher();
      await expect(publishUserRegistered('uid-6', 'a@b.com')).resolves.not.toThrow();
    });
  });
});
