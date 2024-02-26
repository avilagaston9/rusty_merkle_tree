.PHONY: test

test:		
			cd merkle_tree && cargo test
clippy:		
			cd merkle_tree && cargo clippy