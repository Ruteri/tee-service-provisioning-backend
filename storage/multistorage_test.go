package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/ruteri/poc-tee-registry/interfaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockStorageBackend implements interfaces.StorageBackend for testing
type MockStorageBackend struct {
	mock.Mock
	name string
}

func (m *MockStorageBackend) Fetch(ctx context.Context, id interfaces.ContentID, contentType interfaces.ContentType) ([]byte, error) {
	args := m.Called(ctx, id, contentType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockStorageBackend) Store(ctx context.Context, data []byte, contentType interfaces.ContentType) (interfaces.ContentID, error) {
	args := m.Called(ctx, data, contentType)
	return args.Get(0).(interfaces.ContentID), args.Error(1)
}

func (m *MockStorageBackend) Available(ctx context.Context) bool {
	args := m.Called(ctx)
	return args.Bool(0)
}

func (m *MockStorageBackend) Name() string {
	return m.name
}

func (m *MockStorageBackend) LocationURI() string {
	return "mock:"
}

func TestMultiStorageBackend_Available(t *testing.T) {
	// Create test cases
	tests := []struct {
		name     string
		backends []bool
		expected bool
	}{
		{
			name:     "all backends available",
			backends: []bool{true, true, true},
			expected: true,
		},
		{
			name:     "some backends available",
			backends: []bool{false, true, false},
			expected: true,
		},
		{
			name:     "no backends available",
			backends: []bool{false, false, false},
			expected: false,
		},
		{
			name:     "no backends",
			backends: []bool{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock backends
			var backends []interfaces.StorageBackend
			for i, available := range tt.backends {
				mockStorage := &MockStorageBackend{name: fmt.Sprintf("mock-A%x", i)}
				mockStorage.On("Available", mock.Anything).Return(available).Maybe()
				backends = append(backends, mockStorage)
			}

			// Create multi-storage backend
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			multi := NewMultiStorageBackend(backends, logger)

			// Check availability
			result := multi.Available(context.Background())
			assert.Equal(t, tt.expected, result)

			// Verify all mocks were called
			for _, backend := range backends {
				mockStorage := backend.(*MockStorageBackend)
				mockStorage.AssertExpectations(t)
			}
		})
	}
}

func TestMultiStorageBackend_Fetch(t *testing.T) {
	// Test data
	testID := interfaces.ContentID([32]byte{1, 2, 3, 4})
	testData := []byte("test data")
	testErr := errors.New("test error")

	// Create test cases
	tests := []struct {
		name          string
		setupMocks    func() []interfaces.StorageBackend
		expectedData  []byte
		expectedError bool
	}{
		{
			name: "first backend successful",
			setupMocks: func() []interfaces.StorageBackend {
				mock1 := &MockStorageBackend{name: "mock-A"}
				mock1.On("Available", mock.Anything).Return(true)
				mock1.On("Fetch", mock.Anything, testID, interfaces.ConfigType).Return(testData, nil)

				mock2 := &MockStorageBackend{name: "mock-B"}
				// This mock should not be called as the first one succeeds

				return []interfaces.StorageBackend{mock1, mock2}
			},
			expectedData:  testData,
			expectedError: false,
		},
		{
			name: "first backend fails, second succeeds",
			setupMocks: func() []interfaces.StorageBackend {
				mock1 := &MockStorageBackend{name: "mock-A"}
				mock1.On("Available", mock.Anything).Return(true)
				mock1.On("Fetch", mock.Anything, testID, interfaces.ConfigType).Return(nil, testErr)

				mock2 := &MockStorageBackend{name: "mock-B"}
				mock2.On("Available", mock.Anything).Return(true)
				mock2.On("Fetch", mock.Anything, testID, interfaces.ConfigType).Return(testData, nil)

				return []interfaces.StorageBackend{mock1, mock2}
			},
			expectedData:  testData,
			expectedError: false,
		},
		{
			name: "all backends fail",
			setupMocks: func() []interfaces.StorageBackend {
				mock1 := &MockStorageBackend{name: "mock-A"}
				mock1.On("Available", mock.Anything).Return(true)
				mock1.On("Fetch", mock.Anything, testID, interfaces.ConfigType).Return(nil, testErr)

				mock2 := &MockStorageBackend{name: "mock-B"}
				mock2.On("Available", mock.Anything).Return(true)
				mock2.On("Fetch", mock.Anything, testID, interfaces.ConfigType).Return(nil, testErr)

				return []interfaces.StorageBackend{mock1, mock2}
			},
			expectedData:  nil,
			expectedError: true,
		},
		{
			name: "unavailable backends are skipped",
			setupMocks: func() []interfaces.StorageBackend {
				mock1 := &MockStorageBackend{name: "mock-A"}
				mock1.On("Available", mock.Anything).Return(false)
				// Fetch should not be called

				mock2 := &MockStorageBackend{name: "mock-B"}
				mock2.On("Available", mock.Anything).Return(true)
				mock2.On("Fetch", mock.Anything, testID, interfaces.ConfigType).Return(testData, nil)

				return []interfaces.StorageBackend{mock1, mock2}
			},
			expectedData:  testData,
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			backends := tt.setupMocks()
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			multi := NewMultiStorageBackend(backends, logger)

			// Execute
			data, err := multi.Fetch(context.Background(), testID, interfaces.ConfigType)

			// Verify
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedData, data)

			// Verify all mocks were called correctly
			for _, backend := range backends {
				mock := backend.(*MockStorageBackend)
				mock.AssertExpectations(t)
			}
		})
	}
}

func TestMultiStorageBackend_Store(t *testing.T) {
	// Test data
	testID := interfaces.ContentID([32]byte{1, 2, 3, 4})
	testData := []byte("test data")
	testErr := errors.New("test error")

	// Create test cases
	tests := []struct {
		name          string
		setupMocks    func() []interfaces.StorageBackend
		expectedID    interfaces.ContentID
		expectedError bool
	}{
		{
			name: "all backends successful",
			setupMocks: func() []interfaces.StorageBackend {
				mock1 := &MockStorageBackend{name: "mock-A"}
				mock1.On("Available", mock.Anything).Return(true)
				mock1.On("Store", mock.Anything, testData, interfaces.ConfigType).Return(testID, nil)

				mock2 := &MockStorageBackend{name: "mock-B"}
				mock2.On("Available", mock.Anything).Return(true)
				mock2.On("Store", mock.Anything, testData, interfaces.ConfigType).Return(testID, nil)

				return []interfaces.StorageBackend{mock1, mock2}
			},
			expectedID:    testID,
			expectedError: false,
		},
		{
			name: "some backends fail",
			setupMocks: func() []interfaces.StorageBackend {
				mock1 := &MockStorageBackend{name: "mock-A"}
				mock1.On("Available", mock.Anything).Return(true)
				mock1.On("Store", mock.Anything, testData, interfaces.ConfigType).Return(testID, nil)

				mock2 := &MockStorageBackend{name: "mock-B"}
				mock2.On("Available", mock.Anything).Return(true)
				mock2.On("Store", mock.Anything, testData, interfaces.ConfigType).Return(interfaces.ContentID{}, testErr)

				return []interfaces.StorageBackend{mock1, mock2}
			},
			expectedID:    testID,
			expectedError: false,
		},
		{
			name: "all backends fail",
			setupMocks: func() []interfaces.StorageBackend {
				mock1 := &MockStorageBackend{name: "mock-A"}
				mock1.On("Available", mock.Anything).Return(true)
				mock1.On("Store", mock.Anything, testData, interfaces.ConfigType).Return(interfaces.ContentID{}, testErr)

				mock2 := &MockStorageBackend{name: "mock-B"}
				mock2.On("Available", mock.Anything).Return(true)
				mock2.On("Store", mock.Anything, testData, interfaces.ConfigType).Return(interfaces.ContentID{}, testErr)

				return []interfaces.StorageBackend{mock1, mock2}
			},
			expectedID:    interfaces.ContentID{},
			expectedError: true,
		},
		{
			name: "unavailable backends are skipped",
			setupMocks: func() []interfaces.StorageBackend {
				mock1 := &MockStorageBackend{name: "mock-A"}
				mock1.On("Available", mock.Anything).Return(false)
				// Store should not be called

				mock2 := &MockStorageBackend{name: "mock-B"}
				mock2.On("Available", mock.Anything).Return(true)
				mock2.On("Store", mock.Anything, testData, interfaces.ConfigType).Return(testID, nil)

				return []interfaces.StorageBackend{mock1, mock2}
			},
			expectedID:    testID,
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			backends := tt.setupMocks()
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			multi := NewMultiStorageBackend(backends, logger)

			// Execute
			id, err := multi.Store(context.Background(), testData, interfaces.ConfigType)

			// Verify
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expectedID, id)

			// Verify all mocks were called correctly
			for _, backend := range backends {
				mock := backend.(*MockStorageBackend)
				mock.AssertExpectations(t)
			}
		})
	}
}
