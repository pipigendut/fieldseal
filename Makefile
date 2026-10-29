.PHONY: test test-go test-ruby vectors

test: test-go test-ruby

test-go:
	go test ./...

test-ruby:
	bundle exec ruby -Iruby/lib ruby/test/siv_test.rb
	bundle exec ruby -Iruby/lib ruby/test/seal_test.rb
	bundle exec ruby -Iruby/lib ruby/test/active_record_test.rb

vectors:
	UPDATE_VECTORS=1 go test ./go/fieldseal -run TestUpdateVectors -count=1
